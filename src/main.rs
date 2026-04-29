use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, StatusCode},
    response::{Html, IntoResponse, Response},
    Router,
};
use clap::Parser;
use humansize::{format_size, BINARY};
use percent_encoding::{percent_decode_str, utf8_percent_encode, AsciiSet, CONTROLS};
use std::{
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::SystemTime,
};
use tokio::{
    fs::{self, File},
    io::{AsyncReadExt, AsyncSeekExt},
};
use tokio_util::io::ReaderStream;

/// Characters that must be percent-encoded inside a URL path segment.
const PATH_SEGMENT: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'%')
    .add(b'<')
    .add(b'>')
    .add(b'?')
    .add(b'[')
    .add(b'\\')
    .add(b']')
    .add(b'^')
    .add(b'`')
    .add(b'{')
    .add(b'|')
    .add(b'}')
    .add(b'&');

#[derive(Parser)]
#[command(name = "httprd", about = "HTTP file server with resumable-download support")]
struct Args {
    /// Port to listen on
    #[arg(short, long, default_value = "8080")]
    port: u16,

    /// Root directory to serve
    #[arg(short = 'd', long, default_value = ".")]
    dir: PathBuf,

    /// Show directory listing when no index file exists
    #[arg(short, long)]
    index: bool,
}

#[derive(Clone)]
struct AppState {
    root: PathBuf,
    show_index: bool,
}

// ── entry point ─────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let args = Args::parse();

    let root = match args.dir.canonicalize() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("error: cannot access '{}': {}", args.dir.display(), e);
            std::process::exit(1);
        }
    };

    eprintln!(
        "Serving '{}' on port {}{}",
        root.display(),
        args.port,
        if args.index { " (directory listing enabled)" } else { "" },
    );

    let state = Arc::new(AppState { root, show_index: args.index });

    let app = Router::new()
        .fallback(handle_request)
        .with_state(state);

    let listener =
        match tokio::net::TcpListener::bind(format!("0.0.0.0:{}", args.port)).await {
            Ok(l) => l,
            Err(e) => {
                eprintln!("error: cannot bind port {}: {}", args.port, e);
                std::process::exit(1);
            }
        };

    axum::serve(listener, app).await.unwrap();
}

// ── request router ──────────────────────────────────────────────────────────

async fn handle_request(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let uri_path = req.uri().path().to_owned();
    let method   = req.method().as_str().to_owned();
    let headers  = req.headers().clone();

    if method != "GET" && method != "HEAD" {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header(header::ALLOW, "GET, HEAD")
            .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
            .body(Body::from("405 Method Not Allowed"))
            .unwrap();
    }

    // Percent-decode the URI path then build a sandboxed filesystem path.
    let decoded = percent_decode_str(&uri_path)
        .decode_utf8_lossy()
        .into_owned();

    let mut fs_path = state.root.clone();
    for seg in decoded.split('/') {
        match seg {
            "" | "." => {}
            ".."     => {} // silently drop traversal attempts
            s if s.contains('\0') => {
                return plain(StatusCode::BAD_REQUEST, "400 Bad Request");
            }
            s => fs_path.push(s),
        }
    }

    // Resolve symlinks; reject paths that escaped the root.
    let canonical = match fs_path.canonicalize() {
        Ok(p) => p,
        Err(_) => return plain(StatusCode::NOT_FOUND, "404 Not Found"),
    };
    if !canonical.starts_with(&state.root) {
        return plain(StatusCode::FORBIDDEN, "403 Forbidden");
    }

    let meta = match fs::metadata(&canonical).await {
        Ok(m) => m,
        Err(_) => return plain(StatusCode::NOT_FOUND, "404 Not Found"),
    };

    if meta.is_dir() {
        if !uri_path.ends_with('/') {
            return redirect(format!("{}/", uri_path));
        }
        serve_dir(&*state, &canonical, &uri_path).await
    } else if meta.is_file() {
        serve_file(&canonical, meta.len(), &headers, &method).await
    } else {
        plain(StatusCode::NOT_FOUND, "404 Not Found")
    }
}

// ── directory handling ───────────────────────────────────────────────────────

async fn serve_dir(state: &AppState, dir: &Path, uri_path: &str) -> Response {
    // Prefer index.html / index.htm over the generated listing.
    for name in ["index.html", "index.htm"] {
        let p = dir.join(name);
        if let Ok(m) = fs::metadata(&p).await {
            if m.is_file() {
                let empty = axum::http::HeaderMap::new();
                return serve_file(&p, m.len(), &empty, "GET").await;
            }
        }
    }

    if !state.show_index {
        return plain(StatusCode::FORBIDDEN, "403 Forbidden: directory listing is disabled");
    }

    generate_listing(dir, uri_path).await
}

async fn generate_listing(dir: &Path, uri_path: &str) -> Response {
    let mut rd = match fs::read_dir(dir).await {
        Ok(r) => r,
        Err(e) => return plain(StatusCode::INTERNAL_SERVER_ERROR, &format!("500: {}", e)),
    };

    struct Entry {
        name:     String,
        is_dir:   bool,
        size:     u64,
        mode:     u32,
        modified: SystemTime,
        nlink:    u64,
    }

    let mut entries: Vec<Entry> = Vec::new();
    while let Ok(Some(de)) = rd.next_entry().await {
        let name = de.file_name().to_string_lossy().into_owned();
        if let Ok(m) = de.metadata().await {
            entries.push(Entry {
                is_dir:   m.is_dir(),
                size:     m.len(),
                mode:     m.permissions().mode(),
                modified: m.modified().unwrap_or(SystemTime::UNIX_EPOCH),
                nlink:    m.nlink(),
                name,
            });
        }
    }

    // Directories first, then case-insensitive alphabetical.
    entries.sort_by(|a, b| {
        b.is_dir
            .cmp(&a.is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });

    let esc_path = html_escape(uri_path);
    let mut out = format!(
        concat!(
            "<!DOCTYPE html>\n",
            "<html>\n<head>\n",
            "<meta charset=\"utf-8\">\n",
            "<title>Index of {p}</title>\n",
            "<style>\n",
            "body {{ font-family: monospace; margin: 1em 2em; background:#fff; color:#000 }}\n",
            "h2   {{ margin-bottom: .4em }}\n",
            "pre  {{ margin: 0; line-height: 1.6 }}\n",
            "a    {{ color: #0066cc; text-decoration: none }}\n",
            "a:hover {{ text-decoration: underline }}\n",
            "hr   {{ border: none; border-top: 1px solid #ccc; margin: .5em 0 }}\n",
            "</style>\n</head>\n<body>\n",
            "<h2>Index of {p}</h2>\n<hr>\n<pre>\n",
        ),
        p = esc_path,
    );

    // Header row, mimicking `ls -hal`
    out.push_str(&format!(
        "{:<10}  {:>4}  {:>9}  {:<17}  {}\n",
        "Mode", "Lnk", "Size", "Modified", "Name",
    ));

    // Parent-directory link
    if uri_path != "/" {
        out.push_str(&format!(
            "{:<10}  {:>4}  {:>9}  {:<17}  <a href=\"../\">../</a>\n",
            "drwxr-xr-x", "-", "-", "-",
        ));
    }

    for e in &entries {
        let mode_str = fmt_mode(e.mode, e.is_dir);
        let size_str = if e.is_dir {
            "-".to_string()
        } else {
            format_size(e.size, BINARY)
        };
        let time_str = fmt_time(e.modified);

        let raw_name = if e.is_dir {
            format!("{}/", e.name)
        } else {
            e.name.clone()
        };
        let display = html_escape(&raw_name);
        let href = {
            let enc = utf8_percent_encode(&e.name, PATH_SEGMENT).to_string();
            if e.is_dir { format!("{}/", enc) } else { enc }
        };

        out.push_str(&format!(
            "{:<10}  {:>4}  {:>9}  {:<17}  <a href=\"{}\">{}</a>\n",
            mode_str, e.nlink, size_str, time_str, href, display,
        ));
    }

    out.push_str("</pre>\n<hr>\n</body>\n</html>\n");
    let mut resp = Html(out).into_response();
    resp.headers_mut().insert(
        "content-security-policy",
        "default-src 'none'; style-src 'unsafe-inline'".parse().unwrap(),
    );
    resp
}

// ── file serving (full + range) ──────────────────────────────────────────────

async fn serve_file(
    path:      &Path,
    file_size: u64,
    headers:   &axum::http::HeaderMap,
    method:    &str,
) -> Response {
    let content_type = mime_guess::from_path(path)
        .first_or_octet_stream()
        .to_string();

    // Handle HTTP Range request (resumable / partial download).
    if let Some(rv) = headers.get(header::RANGE) {
        if let Ok(rs) = rv.to_str() {
            match parse_range(rs, file_size) {
                Some((start, end)) => {
                    return serve_range(path, start, end, file_size, &content_type, method)
                        .await;
                }
                None => {
                    // Range not satisfiable.
                    return Response::builder()
                        .status(StatusCode::RANGE_NOT_SATISFIABLE)
                        .header(header::CONTENT_RANGE, format!("bytes */{}", file_size))
                        .body(Body::empty())
                        .unwrap();
                }
            }
        }
    }

    // Full-file response.
    let builder = Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, &content_type)
        .header(header::CONTENT_LENGTH, file_size)
        .header(header::ACCEPT_RANGES, "bytes")
        .header("x-content-type-options", "nosniff");

    if method == "HEAD" {
        return builder.body(Body::empty()).unwrap();
    }

    match File::open(path).await {
        Ok(f) => builder
            .body(Body::from_stream(ReaderStream::new(f)))
            .unwrap(),
        Err(_) => plain(StatusCode::INTERNAL_SERVER_ERROR, "500 Internal Server Error"),
    }
}

async fn serve_range(
    path:         &Path,
    start:        u64,
    end:          u64,
    file_size:    u64,
    content_type: &str,
    method:       &str,
) -> Response {
    let length = end - start + 1;

    let builder = Response::builder()
        .status(StatusCode::PARTIAL_CONTENT)
        .header(header::CONTENT_TYPE, content_type)
        .header(header::CONTENT_LENGTH, length)
        .header(
            header::CONTENT_RANGE,
            format!("bytes {}-{}/{}", start, end, file_size),
        )
        .header(header::ACCEPT_RANGES, "bytes")
        .header("x-content-type-options", "nosniff");

    if method == "HEAD" {
        return builder.body(Body::empty()).unwrap();
    }

    let mut file = match File::open(path).await {
        Ok(f) => f,
        Err(_) => return plain(StatusCode::INTERNAL_SERVER_ERROR, "500 Internal Server Error"),
    };

    if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
        return plain(StatusCode::INTERNAL_SERVER_ERROR, "500 Seek failed");
    }

    builder
        .body(Body::from_stream(ReaderStream::new(file.take(length))))
        .unwrap()
}

// ── RFC 7233 range parser ────────────────────────────────────────────────────

/// Parse a `Range: bytes=…` header value.
/// Returns inclusive `(start, end)` positions, or `None` if unsatisfiable.
/// Multi-range requests are reduced to the first range only.
fn parse_range(range_str: &str, file_size: u64) -> Option<(u64, u64)> {
    let spec  = range_str.strip_prefix("bytes=")?;
    let first = spec.split(',').next()?.trim();

    if file_size == 0 {
        return None;
    }

    if let Some(suffix) = first.strip_prefix('-') {
        // Suffix range: `bytes=-N` → last N bytes.
        let n: u64 = suffix.trim().parse().ok()?;
        if n == 0 {
            return None;
        }
        Some((file_size.saturating_sub(n), file_size - 1))
    } else {
        let (s, e) = first.split_once('-')?;
        let start: u64 = s.trim().parse().ok()?;
        if start >= file_size {
            return None;
        }
        let end = if e.trim().is_empty() {
            file_size - 1
        } else {
            e.trim().parse::<u64>().ok()?.min(file_size - 1)
        };
        if start > end {
            return None;
        }
        Some((start, end))
    }
}

// ── formatting helpers ───────────────────────────────────────────────────────

fn fmt_mode(mode: u32, is_dir: bool) -> String {
    const BITS: [(u32, char); 9] = [
        (0o400, 'r'), (0o200, 'w'), (0o100, 'x'),
        (0o040, 'r'), (0o020, 'w'), (0o010, 'x'),
        (0o004, 'r'), (0o002, 'w'), (0o001, 'x'),
    ];
    let mut s = String::with_capacity(10);
    s.push(if is_dir { 'd' } else { '-' });
    for (bit, ch) in BITS {
        s.push(if mode & bit != 0 { ch } else { '-' });
    }
    s
}

/// Format a `SystemTime` like `ls -l`: show time-of-day for recent files,
/// year for files older than ~6 months.
fn fmt_time(t: SystemTime) -> String {
    use chrono::{DateTime, Local};
    let dt: DateTime<Local> = t.into();
    let age = Local::now().signed_duration_since(dt);
    if age.num_seconds() >= 0 && age.num_days() < 182 {
        dt.format("%b %e %H:%M").to_string()
    } else {
        dt.format("%b %e  %Y").to_string()
    }
}

fn html_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            c   => out.push(c),
        }
    }
    out
}

// ── response helpers ─────────────────────────────────────────────────────────

fn plain(status: StatusCode, msg: &str) -> Response {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(Body::from(msg.to_owned()))
        .unwrap()
}

fn redirect(location: String) -> Response {
    Response::builder()
        .status(StatusCode::MOVED_PERMANENTLY)
        .header(header::LOCATION, location)
        .body(Body::empty())
        .unwrap()
}
