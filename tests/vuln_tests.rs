//! Vulnerability test suite for httprd — stdlib only, no TLS dependency.
//!
//! All HTTP traffic goes over plain TCP (127.0.0.1), matching the server's
//! own scope (no HTTPS support required).
//!
//! Test categories mirror vulnerability.md:
//!   PT  – Path Traversal / Directory Traversal   (§3)
//!   ID  – Information Disclosure                  (§11)
//!   AC  – Access Control Misconfiguration         (§10)
//!   RR  – Range Requests / DoS surface            (§8)
//!   RS  – HTTP Response Splitting                 (§5)
//!   GEN – General correctness cross-checks

use std::{
    io::{Read, Write},
    net::TcpStream,
    path::Path,
    process::{Child, Command, Stdio},
    sync::atomic::{AtomicU16, Ordering},
    thread,
    time::Duration,
};
use tempfile::TempDir;

const HTTPRD: &str = env!("CARGO_BIN_EXE_httprd");
static PORT: AtomicU16 = AtomicU16::new(20_100);

fn alloc_port() -> u16 {
    PORT.fetch_add(1, Ordering::SeqCst)
}

// ── Test server harness ──────────────────────────────────────────────────────

struct Server {
    child: Child,
    port:  u16,
}

impl Server {
    fn start(root: &Path, show_index: bool) -> Self {
        let port = alloc_port();
        let mut cmd = Command::new(HTTPRD);
        cmd.arg("-p").arg(port.to_string())
           .arg("-d").arg(root)
           .stdout(Stdio::null())
           .stderr(Stdio::null());
        if show_index {
            cmd.arg("-i");
        }
        let child = cmd.spawn().expect("failed to spawn httprd binary");
        thread::sleep(Duration::from_millis(350));
        Server { child, port }
    }

    fn send(&self, req: &str) -> String {
        raw(self.port, req)
    }
}

impl Drop for Server {
    fn drop(&mut self) {
        self.child.kill().ok();
        self.child.wait().ok();
    }
}

// ── Raw HTTP over TCP (bypasses any URL normalisation) ───────────────────────

fn raw(port: u16, request: &str) -> String {
    let mut s = TcpStream::connect(("127.0.0.1", port))
        .expect("could not connect to test server");
    s.set_read_timeout(Some(Duration::from_secs(5))).unwrap();
    s.write_all(request.as_bytes()).unwrap();
    let mut buf = Vec::new();
    s.read_to_end(&mut buf).unwrap();
    String::from_utf8_lossy(&buf).into_owned()
}

// ── Response parsing helpers ─────────────────────────────────────────────────

fn status_of(resp: &str) -> u16 {
    resp.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Case-insensitive header lookup.  Returns the trimmed value string.
fn header_val(resp: &str, name: &str) -> Option<String> {
    let prefix = format!("{}:", name.to_lowercase());
    for line in resp.lines() {
        if line.to_lowercase().starts_with(&prefix) {
            return Some(line[prefix.len()..].trim().to_owned());
        }
    }
    None
}

/// Everything after the blank line separating headers from body.
fn body_of(resp: &str) -> &str {
    resp.splitn(2, "\r\n\r\n").nth(1).unwrap_or("")
}

// ── HTTP request builders ────────────────────────────────────────────────────

fn req_get(path: &str) -> String {
    format!("GET {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path)
}

fn req_range(path: &str, range: &str) -> String {
    format!(
        "GET {} HTTP/1.1\r\nHost: localhost\r\nRange: {}\r\nConnection: close\r\n\r\n",
        path, range
    )
}

fn req_head(path: &str) -> String {
    format!("HEAD {} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n", path)
}

fn req_method(method: &str, path: &str) -> String {
    format!(
        "{} {} HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        method, path
    )
}

// ── Common test fixture ──────────────────────────────────────────────────────

fn fixture() -> TempDir {
    let dir = TempDir::new().unwrap();
    let d = dir.path();

    // 26-byte ASCII file — convenient for range tests.
    std::fs::write(d.join("hello.txt"), b"ABCDEFGHIJKLMNOPQRSTUVWXYZ").unwrap();
    // Zero-length file — edge case for range requests.
    std::fs::write(d.join("empty.txt"), b"").unwrap();
    // Subdirectory.
    std::fs::create_dir(d.join("sub")).unwrap();
    std::fs::write(d.join("sub/nested.txt"), b"nested").unwrap();

    // Create a second TempDir OUTSIDE the root, then symlink into the root.
    // This simulates a symlink-escape attempt.
    let outside = TempDir::new().unwrap();
    std::fs::write(outside.path().join("secret.txt"), b"OUTSIDE").unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink(outside.path(), d.join("escape_link")).unwrap();
    std::mem::forget(outside); // keep on disk; OS reclaims on process exit

    dir
}

// ════════════════════════════════════════════════════════════════════════════
// PT – Path Traversal  (vulnerability.md §3)
// ════════════════════════════════════════════════════════════════════════════

/// TC-PT-01  Plain ../ sequences must not reach files outside the root.
#[test]
fn pt_01_dotdot_plain() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_get("/../../../etc/passwd")));
    assert!(st == 404 || st == 403,
        "TC-PT-01 FAIL: plain ../ traversal returned {}", st);
}

/// TC-PT-02  URL-encoded %2e%2e must be decoded then the .. dropped.
#[test]
fn pt_02_dotdot_url_encoded() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_get("/%2e%2e/%2e%2e/etc/passwd")));
    assert!(st == 404 || st == 403,
        "TC-PT-02 FAIL: %2e%2e traversal returned {}", st);
}

/// TC-PT-03  Double-encoded %252e%252e must NOT reach parent directories.
/// After one decode: %2e%2e (two literal percent-signs + "2e"); treated as a
/// filename component that doesn't exist → 404.
#[test]
fn pt_03_dotdot_double_encoded() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_get("/%252e%252e/%252e%252e/etc/passwd")));
    assert_ne!(st, 200,
        "TC-PT-03 FAIL: double-encoded traversal returned 200");
}

/// TC-PT-04  Null byte (%00) in a path segment must be rejected — never 200.
#[test]
fn pt_04_null_byte_in_path() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_get("/hello.txt%00.php")));
    assert_ne!(st, 200,
        "TC-PT-04 FAIL: null-byte path returned 200");
}

/// TC-PT-05  A symlink inside the root that points outside must be denied.
#[test]
#[cfg(unix)]
fn pt_05_symlink_escape() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    // escape_link/ → outside TempDir/secret.txt
    let st = status_of(&srv.send(&req_get("/escape_link/secret.txt")));
    assert!(st == 403 || st == 404,
        "TC-PT-05 FAIL: symlink escape returned {}", st);
}

/// TC-PT-06  A path-encoded slash (%2f) must not function as a path separator
/// to enable traversal.
#[test]
fn pt_06_encoded_slash_traversal() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_get("/..%2fetc%2fpasswd")));
    assert_ne!(st, 200,
        "TC-PT-06 FAIL: encoded-slash traversal returned 200");
}

// ════════════════════════════════════════════════════════════════════════════
// ID – Information Disclosure  (vulnerability.md §11)
// ════════════════════════════════════════════════════════════════════════════

/// TC-ID-01  The `Server` response header must not expose software version.
#[test]
fn id_01_no_server_version_header() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_get("/hello.txt"));
    let server_hdr = header_val(&resp, "server").unwrap_or_default();
    assert!(
        !server_hdr.to_lowercase().contains("httprd")
            && !server_hdr.contains("0.1"),
        "TC-ID-01 FAIL: Server header exposes version: {:?}", server_hdr
    );
}

/// TC-ID-02  `X-Content-Type-Options: nosniff` must be present on file responses.
/// Without it, browsers may MIME-sniff a binary file as HTML/JS (§11).
#[test]
fn id_02_x_content_type_options_on_200() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_get("/hello.txt"));
    assert_eq!(status_of(&resp), 200);
    assert_eq!(
        header_val(&resp, "x-content-type-options").as_deref(),
        Some("nosniff"),
        "TC-ID-02 FAIL: X-Content-Type-Options: nosniff missing on 200 response"
    );
}

/// TC-ID-03  `X-Content-Type-Options: nosniff` must also appear on 206 responses.
#[test]
fn id_03_x_content_type_options_on_206() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_range("/hello.txt", "bytes=0-4"));
    assert_eq!(status_of(&resp), 206);
    assert_eq!(
        header_val(&resp, "x-content-type-options").as_deref(),
        Some("nosniff"),
        "TC-ID-03 FAIL: X-Content-Type-Options: nosniff missing on 206 response"
    );
}

/// TC-ID-04  Error body must not leak internal filesystem paths or traces.
#[test]
fn id_04_error_body_not_verbose() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_get("/nonexistent_xyz_file"));
    let body = body_of(&resp).to_lowercase();
    assert!(!body.contains("/home/") && !body.contains("/tmp/"),
        "TC-ID-04 FAIL: 404 body leaks filesystem path");
    assert!(!body.contains("stack") && !body.contains("backtrace"),
        "TC-ID-04 FAIL: 404 body leaks stack trace");
}

/// TC-ID-05  Directory listing must be blocked (403) when -i is not set.
#[test]
fn id_05_listing_requires_index_flag() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_get("/")));
    assert_eq!(st, 403,
        "TC-ID-05 FAIL: listing returned {} without -i flag", st);
}

// ════════════════════════════════════════════════════════════════════════════
// AC – Access Control  (vulnerability.md §10)
// ════════════════════════════════════════════════════════════════════════════

/// TC-AC-01  POST must be rejected with 405 Method Not Allowed.
#[test]
fn ac_01_post_rejected_405() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_method("POST", "/hello.txt")));
    assert_eq!(st, 405, "TC-AC-01 FAIL: POST returned {}", st);
}

/// TC-AC-02  PUT must be rejected with 405.
#[test]
fn ac_02_put_rejected_405() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_method("PUT", "/hello.txt")));
    assert_eq!(st, 405, "TC-AC-02 FAIL: PUT returned {}", st);
}

/// TC-AC-03  DELETE must be rejected with 405.
#[test]
fn ac_03_delete_rejected_405() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_method("DELETE", "/hello.txt")));
    assert_eq!(st, 405, "TC-AC-03 FAIL: DELETE returned {}", st);
}

/// TC-AC-04  PATCH must be rejected with 405.
#[test]
fn ac_04_patch_rejected_405() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let st = status_of(&srv.send(&req_method("PATCH", "/hello.txt")));
    assert_eq!(st, 405, "TC-AC-04 FAIL: PATCH returned {}", st);
}

/// TC-AC-05  Directory listing HTML must carry Content-Security-Policy as
/// defence-in-depth against unexpected XSS via filename content (§10).
#[test]
fn ac_05_csp_on_directory_listing() {
    let root = fixture();
    let srv = Server::start(root.path(), true); // -i flag
    let resp = srv.send(&req_get("/"));
    assert_eq!(status_of(&resp), 200);
    let csp = header_val(&resp, "content-security-policy");
    assert!(csp.is_some(),
        "TC-AC-05 FAIL: directory listing has no Content-Security-Policy header");
}

/// TC-AC-06  Directory listing with -i shows expected entries with links.
#[test]
fn ac_06_listing_content_correct() {
    let root = fixture();
    let srv = Server::start(root.path(), true);
    let resp = srv.send(&req_get("/"));
    assert_eq!(status_of(&resp), 200);
    let body = body_of(&resp);
    assert!(body.contains("hello.txt"), "TC-AC-06 FAIL: hello.txt absent from listing");
    assert!(body.contains("href="), "TC-AC-06 FAIL: no links in listing");
}

// ════════════════════════════════════════════════════════════════════════════
// RR – Range Requests / DoS surface  (vulnerability.md §8)
// ════════════════════════════════════════════════════════════════════════════

/// TC-RR-01  Valid range returns 206 with correct bytes.
#[test]
fn rr_01_valid_range_206() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_range("/hello.txt", "bytes=0-4"));
    assert_eq!(status_of(&resp), 206, "TC-RR-01 FAIL");
    assert_eq!(body_of(&resp), "ABCDE");
}

/// TC-RR-02  Open-ended range bytes=N- serves from N to end of file.
#[test]
fn rr_02_open_ended_range() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_range("/hello.txt", "bytes=20-"));
    assert_eq!(status_of(&resp), 206);
    assert_eq!(body_of(&resp), "UVWXYZ");
}

/// TC-RR-03  Suffix range bytes=-N serves the last N bytes.
#[test]
fn rr_03_suffix_range() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_range("/hello.txt", "bytes=-5"));
    assert_eq!(status_of(&resp), 206);
    assert_eq!(body_of(&resp), "VWXYZ");
}

/// TC-RR-04  Range end beyond file size must be clamped, not error.
#[test]
fn rr_04_end_clamped_to_eof() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_range("/hello.txt", "bytes=20-9999"));
    assert_eq!(status_of(&resp), 206);
    assert_eq!(body_of(&resp), "UVWXYZ");
}

/// TC-RR-05  Start >= file size must return 416 Range Not Satisfiable.
#[test]
fn rr_05_start_beyond_eof_416() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    assert_eq!(status_of(&srv.send(&req_range("/hello.txt", "bytes=999-1000"))), 416,
        "TC-RR-05 FAIL");
}

/// TC-RR-06  start > end must return 416.
#[test]
fn rr_06_start_gt_end_416() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    assert_eq!(status_of(&srv.send(&req_range("/hello.txt", "bytes=10-5"))), 416,
        "TC-RR-06 FAIL");
}

/// TC-RR-07  Non-numeric range spec must return 416.
#[test]
fn rr_07_malformed_range_416() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    assert_eq!(status_of(&srv.send(&req_range("/hello.txt", "bytes=abc-def"))), 416,
        "TC-RR-07 FAIL");
}

/// TC-RR-08  Any range on a zero-length file must return 416.
#[test]
fn rr_08_range_on_empty_file_416() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    assert_eq!(status_of(&srv.send(&req_range("/empty.txt", "bytes=0-0"))), 416,
        "TC-RR-08 FAIL");
}

/// TC-RR-09  u64::MAX as end value must not panic; must be clamped and return 206.
#[test]
fn rr_09_u64_max_end_clamped() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_range("/hello.txt", "bytes=0-18446744073709551615"));
    assert_eq!(status_of(&resp), 206, "TC-RR-09 FAIL");
    assert_eq!(body_of(&resp).len(), 26, "TC-RR-09 FAIL: should return whole file");
}

// ════════════════════════════════════════════════════════════════════════════
// RS – HTTP Response Splitting  (vulnerability.md §5)
// ════════════════════════════════════════════════════════════════════════════

/// TC-RS-01  URL-encoded CRLF (%0d%0a) in the request path must never appear
/// as a raw header name/value in the response.
#[test]
fn rs_01_crlf_not_injected_into_headers() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    // The %0d%0a will be decoded to \r\n by our handler, but the resulting
    // weird path component won't exist → 404 before any header reflecting
    // the value could occur.
    let resp = srv.send(&req_get("/sub%0d%0aX-Evil:%20injected"));
    assert!(
        !resp.to_lowercase().contains("x-evil"),
        "TC-RS-01 FAIL: injected header name appeared in response"
    );
}

// ════════════════════════════════════════════════════════════════════════════
// GEN – General correctness
// ════════════════════════════════════════════════════════════════════════════

/// TC-GEN-01  HEAD must return headers (with correct metadata) but no body.
#[test]
fn gen_01_head_no_body() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_head("/hello.txt"));
    assert_eq!(status_of(&resp), 200);
    assert!(body_of(&resp).is_empty(),
        "TC-GEN-01 FAIL: HEAD response has non-empty body");
}

/// TC-GEN-02  GET serves the file with 200 and Accept-Ranges: bytes advertised.
#[test]
fn gen_02_get_200_with_accept_ranges() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_get("/hello.txt"));
    assert_eq!(status_of(&resp), 200);
    assert_eq!(
        header_val(&resp, "accept-ranges").as_deref(),
        Some("bytes"),
        "TC-GEN-02 FAIL: Accept-Ranges: bytes not advertised"
    );
    assert_eq!(body_of(&resp), "ABCDEFGHIJKLMNOPQRSTUVWXYZ");
}

/// TC-GEN-03  Directory without trailing slash must redirect 301 → with slash.
#[test]
fn gen_03_dir_redirect_adds_slash() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_get("/sub")); // no trailing slash
    assert_eq!(status_of(&resp), 301,
        "TC-GEN-03 FAIL: /sub returned {}", status_of(&resp));
    let loc = header_val(&resp, "location").unwrap_or_default();
    assert!(loc.ends_with("/sub/"),
        "TC-GEN-03 FAIL: Location is {:?}", loc);
}

/// TC-GEN-04  Content-Range on 206 must be correctly formatted.
#[test]
fn gen_04_content_range_header_format() {
    let root = fixture();
    let srv = Server::start(root.path(), false);
    let resp = srv.send(&req_range("/hello.txt", "bytes=5-9"));
    assert_eq!(status_of(&resp), 206);
    let cr = header_val(&resp, "content-range").unwrap_or_default();
    assert_eq!(cr, "bytes 5-9/26",
        "TC-GEN-04 FAIL: unexpected Content-Range: {:?}", cr);
}
