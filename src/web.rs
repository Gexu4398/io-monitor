//! `iomon web`：本机打开的 IO 查看页。
//!
//! 采样在后台进行，HTTP 只负责把最近一帧 JSON 和页面发出去。
//! 不引入第三方库，页面随二进制一起编译进去。

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::process::exit;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::sleep;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::records::{AlertBook, ProcSnap};
use crate::diskstats::{self, DiskStats};
use crate::iotop::{IoFrame, ProcRate, ProcSampler};
use crate::json::{json_str, push_num};

const PAGE: &str = include_str!("assets/index.html");
const ROW_LIMIT: usize = 200;
/// 同时服务的连接上限；超出的连接直接关闭，避免线程无上限增长。
const MAX_CONNECTIONS: usize = 64;

pub struct WebOptions {
    pub addr: String,
    pub interval: f64,
}

pub fn parse_args(args: &[String]) -> Result<WebOptions, String> {
    let mut opts = WebOptions {
        addr: "127.0.0.1:8080".to_string(),
        interval: 1.0,
    };
    let mut positional = Vec::new();
    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{}", USAGE);
                exit(0);
            }
            "-l" | "--listen" => {
                let v = it
                    .next()
                    .ok_or_else(|| "-l/--listen 需要一个地址，如 127.0.0.1:8080".to_string())?;
                opts.addr = normalize_addr(v)?;
            }
            s if s.starts_with('-') => return Err(format!("未知选项: {}", s)),
            s => positional.push(s.to_string()),
        }
    }
    if positional.len() > 1 {
        return Err("位置参数过多，最多一个间隔秒数".to_string());
    }
    if let Some(s) = positional.first() {
        let v: f64 = s.parse().map_err(|_| format!("无效的间隔秒数: {}", s))?;
        if !v.is_finite() || v < 0.5 {
            return Err("间隔秒数至少为 0.5（全量扫描线程很贵）".to_string());
        }
        opts.interval = v;
    }
    Ok(opts)
}

pub const USAGE: &str = "\
iomon web —— 在浏览器里查看 IO

用法:
    iomon web [间隔秒数] [-l 地址]

默认监听 127.0.0.1:8080（只有本机能访问），采样间隔 1 秒。
打开 http://127.0.0.1:8080

选项:
    -l, --listen ADDR   监听地址。只写端口（如 9090）同样只绑本机；
                        要让局域网访问需写全地址，如 0.0.0.0:8080
    -h, --help          显示本帮助

页面上可以切换「仅活动 / 按进程」和搜索，不必重启。
记录页在 /records，默认记下 IO 占比达到 20% 的进程，可在页面上改阈值。

页面会显示全部进程的命令行，请勿在没有防火墙或反向代理认证的
情况下暴露到不可信网络。
";

fn normalize_addr(raw: &str) -> Result<String, String> {
    // 只写端口的缩写形式一律只绑本机；要对外监听必须写全地址。
    if let Some(port) = raw.strip_prefix(':') {
        parse_port(port)?;
        return Ok(format!("127.0.0.1:{}", port));
    }
    if !raw.contains(':') && raw.chars().all(|c| c.is_ascii_digit()) {
        parse_port(raw)?;
        return Ok(format!("127.0.0.1:{}", raw));
    }
    let (host, port) = raw
        .rsplit_once(':')
        .ok_or_else(|| format!("地址需要带端口: {}", raw))?;
    if host.is_empty() {
        return Err(format!("地址缺少主机名: {}", raw));
    }
    parse_port(port)?;
    Ok(raw.to_string())
}

fn parse_port(port: &str) -> Result<u16, String> {
    port.parse::<u16>()
        .map_err(|_| format!("无效的端口: {}", port))
        .and_then(|p| {
            if p == 0 {
                Err("端口不能为 0".to_string())
            } else {
                Ok(p)
            }
        })
}

struct DiskSample {
    at: Instant,
    disks: Vec<DiskStats>,
}

struct DeviceRate {
    name: String,
    r_s: f64,
    w_s: f64,
    read_bps: f64,
    write_bps: f64,
    await_ms: f64,
    util_pct: f64,
}

fn sample_devices(prev: &mut Option<DiskSample>) -> Vec<DeviceRate> {
    let cur = match diskstats::read() {
        Ok(d) => d,
        Err(_) => return Vec::new(),
    };
    let now = Instant::now();
    let Some(old) = prev.as_ref() else {
        *prev = Some(DiskSample {
            at: now,
            disks: cur,
        });
        return Vec::new();
    };
    let elapsed = now.duration_since(old.at).as_secs_f64().max(0.001);
    let mut rates: Vec<DeviceRate> = diskstats::rates(&old.disks, &cur, elapsed)
        .into_iter()
        .filter(|r| !diskstats::is_pseudo_device(&r.device))
        .map(|r| DeviceRate {
            name: r.device,
            r_s: r.r_s,
            w_s: r.w_s,
            read_bps: r.rk_bps * 1024.0,
            write_bps: r.wk_bps * 1024.0,
            await_ms: r.await_ms,
            util_pct: r.util_pct,
        })
        .collect();
    rates.sort_by(|a, b| {
        b.util_pct
            .total_cmp(&a.util_pct)
            .then_with(|| (b.read_bps + b.write_bps).total_cmp(&(a.read_bps + a.write_bps)))
            .then_with(|| a.name.cmp(&b.name))
    });
    rates.truncate(12);
    *prev = Some(DiskSample {
        at: now,
        disks: cur,
    });
    rates
}

struct Hub {
    live: String,
    book: AlertBook,
    threshold: f64,
    host: String,
    interval: f64,
    delayacct: bool,
}

fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_else(|_| "localhost".to_string())
        .trim()
        .to_string()
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn aggregate_procs(rows: &[ProcRate]) -> Vec<ProcSnap> {
    let mut map: HashMap<u32, ProcSnap> = HashMap::new();
    for row in rows {
        let entry = map.entry(row.pid).or_insert(ProcSnap {
            pid: row.pid,
            user: row.user.clone(),
            command: row.command.clone(),
            io: 0.0,
            read: 0.0,
            write: 0.0,
        });
        entry.io = (entry.io + row.io_pct).min(100.0);
        entry.read += row.read_bps;
        entry.write += row.write_bps;
        if row.tid == row.pid || entry.command.is_empty() {
            entry.command = row.command.clone();
            entry.user = row.user.clone();
        }
    }
    map.into_values().collect()
}

fn sampler_loop(hub: Arc<Mutex<Hub>>, interval: f64) {
    if !cfg!(target_os = "linux") {
        let body = json_error(
            0,
            "这台机器没有 /proc。采集只能在 Linux 上运行；页面本身可以用 ?preview=1 看布局。",
        );
        hub.lock().unwrap_or_else(|e| e.into_inner()).live = body;
        return;
    }
    let host = hostname();
    let mut procs = ProcSampler::open();
    let mut disks: Option<DiskSample> = None;
    let mut seq = 0u64;
    loop {
        let frame = procs.poll(ROW_LIMIT);
        let devices = sample_devices(&mut disks);
        let snaps = if frame.ready {
            aggregate_procs(&frame.rows)
        } else {
            Vec::new()
        };
        seq = seq.wrapping_add(1);
        let mut guard = hub.lock().unwrap_or_else(|e| e.into_inner());
        let threshold = guard.threshold;
        guard.book.set_threshold(threshold);
        if frame.ready {
            guard.book.ingest(
                unix_now(),
                frame.elapsed_s,
                frame.actual_read,
                frame.actual_write,
                &snaps,
            );
        }
        guard.delayacct = frame.delayacct;
        guard.live = json_frame(seq, interval, &host, &frame, &devices, guard.book.open_count());
        drop(guard);
        sleep(Duration::from_secs_f64(interval));
    }
}

pub fn serve(opts: WebOptions) {
    let listener = match TcpListener::bind(&opts.addr) {
        Ok(l) => l,
        Err(e) => {
            eprintln!("错误: 监听 {} 失败: {}", opts.addr, e);
            exit(1);
        }
    };
    let browse = browse_hint(&opts.addr);
    println!(
        "iomon web —— {}  采样间隔 {}s，Ctrl+C 退出",
        browse, opts.interval
    );

    let interval = opts.interval;
    let now = unix_now();
    let book = AlertBook::open(crate::records::data_dir(), 20.0, now);
    let threshold = book.threshold;
    let published = Arc::new(Mutex::new(Hub {
        live: json_pending(),
        book,
        threshold,
        host: hostname(),
        interval,
        delayacct: true,
    }));
    let worker = Arc::clone(&published);
    std::thread::spawn(move || sampler_loop(worker, interval));

    let live = Arc::new(AtomicUsize::new(0));
    for conn in listener.incoming() {
        let mut stream = match conn {
            Ok(s) => s,
            Err(_) => continue,
        };
        if live.load(Ordering::Relaxed) >= MAX_CONNECTIONS {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            continue;
        }
        live.fetch_add(1, Ordering::Relaxed);
        let published = Arc::clone(&published);
        let counter = Arc::clone(&live);
        std::thread::spawn(move || {
            let _ = handle(&mut stream, &published);
            counter.fetch_sub(1, Ordering::Relaxed);
        });
    }
}

fn browse_hint(addr: &str) -> String {
    if let Some((host, port)) = addr.rsplit_once(':') {
        if host == "0.0.0.0" || host == "::" {
            return format!("http://127.0.0.1:{}", port);
        }
    }
    format!("http://{}", addr)
}

fn handle(stream: &mut TcpStream, hub: &Mutex<Hub>) -> std::io::Result<()> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
    let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    // 先读出完整请求头，再按 Content-Length 把 body 读完
    loop {
        if buf.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        match stream.read(&mut chunk) {
            Ok(0) => break,
            Ok(k) => buf.extend_from_slice(&chunk[..k]),
            Err(_) => break,
        }
        if buf.len() > 64 * 1024 {
            break;
        }
    }
    if let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
        let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
        let want = content_length(&head).unwrap_or(0);
        while buf.len() < header_end + 4 + want {
            match stream.read(&mut chunk) {
                Ok(0) | Err(_) => break,
                Ok(k) => buf.extend_from_slice(&chunk[..k]),
            }
        }
    }
    let req = String::from_utf8_lossy(&buf);
    let mut parts = req
        .lines()
        .next()
        .unwrap_or("")
        .split_whitespace();
    let method = parts.next().unwrap_or("GET");
    let raw = parts.next().unwrap_or("/");
    let path = raw.split('?').next().unwrap_or("/");
    match path {
        "/" | "/index.html" | "/records" => {
            write_resp(stream, "200 OK", "text/html; charset=utf-8", PAGE.as_bytes())
        }
        "/api/live" => {
            let guard = lock_hub(hub);
            let body = guard.live.clone();
            write_resp(stream, "200 OK", "application/json; charset=utf-8", body.as_bytes())
        }
        "/api/records" => {
            let mut guard = lock_hub(hub);
            // 改阈值是写操作，只接受 POST；GET 带着阈值参数一律拒绝，
            // 避免被浏览器预取或爬虫误触发
            if method != "POST" {
                if query_param(raw, "threshold").is_some() {
                    return write_resp(
                        stream,
                        "405 Method Not Allowed",
                        "text/plain; charset=utf-8",
                        b"use POST to change threshold",
                    );
                }
            } else if let Some(value) = body_param(&req, "threshold").and_then(|s| s.parse::<f64>().ok()) {
                let value = value.clamp(1.0, 100.0);
                guard.threshold = value;
                guard.book.set_threshold(value);
            }
            let now = unix_now();
            let from = query_param(raw, "from").and_then(|s| s.parse().ok()).unwrap_or(0);
            let to = query_param(raw, "to").and_then(|s| s.parse().ok()).unwrap_or(0);
            let body = guard.book.to_json(guard.delayacct, &guard.host, guard.interval, now, from, to);
            drop(guard);
            write_resp(stream, "200 OK", "application/json; charset=utf-8", body.as_bytes())
        }
        _ => write_resp(stream, "404 Not Found", "text/plain; charset=utf-8", b"not found"),
    }
}

/// 持锁线程 panic 后 Mutex 会中毒，这里恢复数据继续用，不让整个服务连锁倒下。
fn lock_hub(hub: &Mutex<Hub>) -> std::sync::MutexGuard<'_, Hub> {
    hub.lock().unwrap_or_else(|e| e.into_inner())
}

/// 从请求体（形如 `threshold=20`）取参数。只支持前端实际发送的简单格式。
fn body_param(req: &str, key: &str) -> Option<String> {
    let body = req.split_once("\r\n\r\n")?.1;
    for part in body.split('&') {
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        if name.trim() == key {
            return Some(value.trim().to_string());
        }
    }
    None
}

fn query_param(raw: &str, key: &str) -> Option<String> {
    let query = raw.split_once('?')?.1;
    for part in query.split('&') {
        let (name, value) = part.split_once('=').unwrap_or((part, ""));
        if name == key {
            return Some(value.to_string());
        }
    }
    None
}

fn content_length(head: &str) -> Option<usize> {
    for line in head.lines() {
        if let Some(rest) = line.strip_prefix("Content-Length:").or_else(|| line.strip_prefix("content-length:")) {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn write_resp(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) -> std::io::Result<()> {
    let header = format!(
        "HTTP/1.1 {status}\r\nContent-Type: {ctype}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(header.as_bytes())?;
    stream.write_all(body)?;
    Ok(())
}

fn json_pending() -> String {
    "{\"ok\":true,\"seq\":0,\"ready\":false,\"error\":null,\"host\":\"\",\"interval_s\":0,\"elapsed_s\":0,\"delayacct\":true,\"skipped\":0,\"threads\":0,\"alerts\":0,\"total_read\":0,\"total_write\":0,\"actual_read\":0,\"actual_write\":0,\"devices\":[],\"rows\":[]}".to_string()
}

fn json_error(seq: u64, message: &str) -> String {
    format!(
        "{{\"ok\":false,\"seq\":{},\"ready\":false,\"error\":{},\"host\":\"\",\"interval_s\":0,\"elapsed_s\":0,\"delayacct\":false,\"skipped\":0,\"threads\":0,\"alerts\":0,\"total_read\":0,\"total_write\":0,\"actual_read\":0,\"actual_write\":0,\"devices\":[],\"rows\":[]}}",
        seq,
        json_str(message)
    )
}

fn json_frame(
    seq: u64,
    interval: f64,
    host: &str,
    frame: &IoFrame,
    devices: &[DeviceRate],
    alerts: usize,
) -> String {
    let mut out = String::with_capacity(4096);
    out.push_str("{\"ok\":true,\"seq\":");
    out.push_str(&seq.to_string());
    out.push_str(",\"ready\":");
    out.push_str(if frame.ready { "true" } else { "false" });
    out.push_str(",\"error\":null,\"host\":");
    out.push_str(&json_str(host));
    out.push_str(",\"interval_s\":");
    push_num(&mut out, interval);
    out.push_str(",\"elapsed_s\":");
    push_num(&mut out, frame.elapsed_s);
    out.push_str(",\"delayacct\":");
    out.push_str(if frame.delayacct { "true" } else { "false" });
    out.push_str(",\"skipped\":");
    out.push_str(&frame.skipped.to_string());
    out.push_str(",\"threads\":");
    out.push_str(&frame.threads.to_string());
    out.push_str(",\"alerts\":");
    out.push_str(&alerts.to_string());
    out.push_str(",\"total_read\":");
    push_num(&mut out, frame.total_read);
    out.push_str(",\"total_write\":");
    push_num(&mut out, frame.total_write);
    out.push_str(",\"actual_read\":");
    push_num(&mut out, frame.actual_read);
    out.push_str(",\"actual_write\":");
    push_num(&mut out, frame.actual_write);
    out.push_str(",\"devices\":[");
    for (i, d) in devices.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"name\":");
        out.push_str(&json_str(&d.name));
        out.push_str(",\"r_s\":");
        push_num(&mut out, d.r_s);
        out.push_str(",\"w_s\":");
        push_num(&mut out, d.w_s);
        out.push_str(",\"read_bps\":");
        push_num(&mut out, d.read_bps);
        out.push_str(",\"write_bps\":");
        push_num(&mut out, d.write_bps);
        out.push_str(",\"await_ms\":");
        push_num(&mut out, d.await_ms);
        out.push_str(",\"util_pct\":");
        push_num(&mut out, d.util_pct);
        out.push('}');
    }
    out.push_str("],\"rows\":[");
    for (i, r) in frame.rows.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        out.push_str("{\"tid\":");
        out.push_str(&r.tid.to_string());
        out.push_str(",\"pid\":");
        out.push_str(&r.pid.to_string());
        out.push_str(",\"prio\":");
        out.push_str(&json_str(&r.prio));
        out.push_str(",\"user\":");
        out.push_str(&json_str(&r.user));
        out.push_str(",\"read_bps\":");
        push_num(&mut out, r.read_bps);
        out.push_str(",\"write_bps\":");
        push_num(&mut out, r.write_bps);
        out.push_str(",\"swapin_pct\":");
        push_num(&mut out, r.swapin_pct);
        out.push_str(",\"io_pct\":");
        push_num(&mut out, r.io_pct);
        out.push_str(",\"command\":");
        out.push_str(&json_str(&r.command));
        out.push('}');
    }
    out.push_str("]}");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_string_escapes() {
        assert_eq!(json_str("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(json_str("行\n"), "\"行\\n\"");
    }

    #[test]
    fn listen_addr_forms() {
        assert_eq!(normalize_addr("9090").unwrap(), "127.0.0.1:9090");
        assert_eq!(normalize_addr(":9090").unwrap(), "127.0.0.1:9090");
        assert_eq!(normalize_addr("127.0.0.1:9090").unwrap(), "127.0.0.1:9090");
        assert_eq!(normalize_addr("0.0.0.0:9090").unwrap(), "0.0.0.0:9090");
        assert!(normalize_addr("127.0.0.1").is_err());
        assert!(normalize_addr("0").is_err());
    }

    #[test]
    fn error_json_is_object() {
        let s = json_error(3, "x");
        assert!(s.contains("\"ok\":false"));
        assert!(s.contains("\"seq\":3"));
    }

    #[test]
    fn body_param_finds_threshold() {
        let req = "POST /api/records HTTP/1.1\r\nContent-Length: 13\r\n\r\nthreshold=20";
        assert_eq!(body_param(req, "threshold").as_deref(), Some("20"));
        assert_eq!(body_param(req, "missing"), None);
    }

    #[test]
    fn content_length_parsed() {
        let head = "POST /api/records HTTP/1.1\r\nContent-Length: 13\r\nHost: x";
        assert_eq!(content_length(head), Some(13));
        assert_eq!(content_length("GET / HTTP/1.1\r\nHost: x"), None);
    }
}
