//! iotop 风格的进程/线程 IO 排行视图（`iomon top`）。
//!
//! 每个采样间隔遍历 /proc 下全部 PID 及其 task/TID。磁盘字节来自
//! /proc/<pid>/task/<tid>/io（写字节扣除 cancelled_write_bytes，与 iotop 相同）。
//! PRIO 来自 ioprio_get。IO% / SWAPIN% 优先用 taskstats 的纳秒延迟；
//! 没有 CAP_NET_ADMIN 时，IO% 改用 stat 的 blkio tick，SWAPIN 为 0。
//! Actual 来自 /proc/vmstat 的 pgpgin/pgpgout，而不是把 diskstats 里的
//! 整盘和分区加在一起。

use std::collections::HashMap;
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::ioprio;
use crate::proc_io;
use crate::syscall;
use crate::taskstats::{self, Taskstats};
use crate::vmstat;

/// 展示单元的身份信息（线程级为单个线程，进程级为聚合后的线程组）。
#[derive(Clone)]
struct Ident {
    /// 线程级为 TID，进程级为 PID
    id: u32,
    /// 线程名（/proc/<tid>/stat 的 comm）
    comm: String,
    /// 已格式化的命令行；内核线程为空串
    cmdline: String,
    /// 线程所属进程。线程视图里 id 是 TID，进程视图里 id 与 pid 相同。
    pid: u32,
    /// real uid；读取失败为 u32::MAX（显示为 "?"）
    uid: u32,
    /// iotop 风格的 IO 优先级，如 be/4、rt/4、idle
    prio: String,
}

/// 一个展示单元自启动以来的原始 IO 计数。
struct Agg {
    read_bytes: u64,
    write_bytes: u64,
    cancelled_write_bytes: u64,
    /// blkio 延迟累计，纳秒（taskstats，或由 blkio tick 换算）
    blkio_delay_ns: u64,
    /// 换入延迟累计，纳秒；没有 taskstats 时为 0
    swapin_delay_ns: u64,
    ident: Ident,
}

/// 一次全量采样。
struct Scan {
    at: Instant,
    aggs: HashMap<u32, Agg>,
    /// 因进程退出或权限原因未能读取 io/stat 的线程数
    skipped: usize,
    /// /proc/vmstat 换算后的累计读/写字节；读失败为 None，避免用 0 制造假速率
    vm_read: Option<u64>,
    vm_write: Option<u64>,
}

/// 一个间隔内的展示速率行。
struct Row {
    read_bps: f64,
    write_bps: f64,
    swapin_pct: f64,
    /// 本间隔阻塞在磁盘 IO 上的时间占比，最大 100（与 iotop 相同）
    io_pct: f64,
    ident: Ident,
}

pub struct TopOptions {
    pub interval: f64,
    pub count: Option<u64>,
    /// -P：按进程（线程组）聚合展示，否则按线程
    pub per_process: bool,
    /// 为 false 时只展示有 IO 活动的条目（-o）
    pub show_idle: bool,
    /// 最多展示的行数
    pub rows: usize,
    /// 用户显式传了 -n 时不再按终端高度调整
    pub rows_explicit: bool,
}

/// 列出目录下名字全为数字的子目录（即 /proc 下的 PID、task 下的 TID）。
fn list_numeric_dirs(path: &str) -> Vec<u32> {
    let mut out = Vec::new();
    if let Ok(rd) = fs::read_dir(path) {
        for entry in rd.flatten() {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if !name.is_empty() && name.chars().all(|c| c.is_ascii_digit()) {
                if let Ok(n) = name.parse::<u32>() {
                    out.push(n);
                }
            }
        }
    }
    out
}

/// 从 /proc/<pid>/status 读取 real uid；失败返回 None。
fn read_uid(pid: u32) -> Option<u32> {
    let content = fs::read_to_string(format!("/proc/{}/status", pid)).ok()?;
    for line in content.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// 将 cmdline 原始字节（NUL 分隔）格式化为单行；内核线程/已退出进程为空串。
fn fmt_cmdline(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .trim_end_matches('\0')
        .replace('\0', " ")
        .trim()
        .to_string()
}

/// 内核 task_delayacct 为 0 时，IO% 和 SWAPIN 的分子一直是 0。
/// 没有这个文件的旧内核是编译期常开，按已开启处理。
fn delayacct_enabled() -> bool {
    match fs::read_to_string("/proc/sys/kernel/task_delayacct") {
        Ok(s) => s.trim() != "0",
        Err(_) => true,
    }
}

/// 遍历全部 PID/TID 完成一次采样。线程随时可能退出，读取失败只计数不报错。
fn scan(per_process: bool, ts: &mut Option<Taskstats>) -> Scan {
    let mut aggs = HashMap::new();
    let mut skipped = 0usize;

    for pid in list_numeric_dirs("/proc") {
        let uid = read_uid(pid).unwrap_or(u32::MAX);
        let cmdline = fmt_cmdline(&fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default());

        for tid in list_numeric_dirs(&format!("/proc/{}/task", pid)) {
            // 顶层 /proc/<tid>/io|stat 返回的是线程组聚合值，
            // 线程级监控必须走 task 路径
            let (io, stat) = match (
                proc_io::read_thread_io(pid, tid),
                proc_io::read_thread_stat(pid, tid),
            ) {
                (Ok(io), Ok(stat)) => (io, stat),
                _ => {
                    skipped += 1;
                    continue;
                }
            };
            let (blkio_ns, swapin_ns) = match ts.as_mut().and_then(|t| t.query(tid)) {
                Some(d) => (d.blkio_ns, d.swapin_ns),
                // 1 tick = 10ms = 10_000_000ns，与 taskstats 的纳秒对齐后再做差。
                None => (stat.blkio_ticks.saturating_mul(10_000_000), 0),
            };
            let ident = Ident {
                id: if per_process { pid } else { tid },
                pid,
                comm: stat.comm,
                cmdline: cmdline.clone(),
                uid,
                prio: ioprio::read_ioprio(tid, stat.nice, stat.policy),
            };
            let key = if per_process { pid } else { tid };
            let e = aggs.entry(key).or_insert(Agg {
                read_bytes: 0,
                write_bytes: 0,
                cancelled_write_bytes: 0,
                blkio_delay_ns: 0,
                swapin_delay_ns: 0,
                ident: ident.clone(),
            });
            e.read_bytes += io.read_bytes;
            e.write_bytes += io.write_bytes;
            e.cancelled_write_bytes += io.cancelled_write_bytes;
            e.blkio_delay_ns += blkio_ns;
            e.swapin_delay_ns += swapin_ns;
            // 进程级展示时用主线程（leader）的名字和优先级，与 ps 一致
            if tid == pid {
                e.ident = ident;
            }
        }
    }

    let (vm_read, vm_write) = match vmstat::read() {
        Some((r, w)) => (Some(r), Some(w)),
        None => (None, None),
    };
    Scan {
        at: Instant::now(),
        aggs,
        skipped,
        vm_read,
        vm_write,
    }
}

/// 延迟纳秒占采样时长的百分比。iotop 用 delta/(秒*1e7) 并封顶 100。
fn delay_pct(delta_ns: u64, elapsed_s: f64) -> f64 {
    if !(elapsed_s > 0.0) {
        return 0.0;
    }
    (delta_ns as f64 / (elapsed_s * 10_000_000.0)).min(100.0)
}

/// 由前后两次采样计算差值速率；只在两次中都出现的条目上配对（新进程差值无从谈起）。
fn diff(prev: &Scan, cur: &Scan, elapsed_s: f64) -> Vec<Row> {
    cur.aggs
        .iter()
        .filter_map(|(id, c)| {
            let p = prev.aggs.get(id)?;
            let write_delta = c.write_bytes.saturating_sub(p.write_bytes);
            let cancel_delta = c
                .cancelled_write_bytes
                .saturating_sub(p.cancelled_write_bytes);
            Some(Row {
                read_bps: c.read_bytes.saturating_sub(p.read_bytes) as f64 / elapsed_s,
                write_bps: write_delta.saturating_sub(cancel_delta) as f64 / elapsed_s,
                swapin_pct: delay_pct(
                    c.swapin_delay_ns.saturating_sub(p.swapin_delay_ns),
                    elapsed_s,
                ),
                io_pct: delay_pct(c.blkio_delay_ns.saturating_sub(p.blkio_delay_ns), elapsed_s),
                ident: c.ident.clone(),
            })
        })
        .collect()
}

/// 排序：按读写速率合计降序，其次 IO%、SWAPIN，最后按 ID 保证稳定。
fn order(rows: &mut [Row]) {
    rows.sort_by(|a, b| {
        (b.read_bps + b.write_bps)
            .total_cmp(&(a.read_bps + a.write_bps))
            .then_with(|| b.io_pct.total_cmp(&a.io_pct))
            .then_with(|| b.swapin_pct.total_cmp(&a.swapin_pct))
            .then_with(|| a.ident.id.cmp(&b.ident.id))
    });
}

/// 设备实际吞吐（B/s）。来自 vmstat 的 pgpgin/pgpgout，与 iotop 的 Actual 相同。
fn actual_bps(prev: &Scan, cur: &Scan, elapsed_s: f64) -> (f64, f64) {
    match (prev.vm_read, prev.vm_write, cur.vm_read, cur.vm_write) {
        (Some(pr), Some(pw), Some(cr), Some(cw)) if elapsed_s > 0.0 => (
            cr.saturating_sub(pr) as f64 / elapsed_s,
            cw.saturating_sub(pw) as f64 / elapsed_s,
        ),
        _ => (0.0, 0.0),
    }
}

/// 终端下一屏能放下的行数，以及命令列可用的字符数。
fn view_limits(opts: &TopOptions, tty: bool) -> (usize, usize) {
    let (rows, cols) = if tty {
        syscall::tty_size().unwrap_or((0, 0))
    } else {
        (0, 0)
    };
    let n = if opts.rows_explicit {
        opts.rows
    } else if rows > 5 {
        rows - 5
    } else {
        opts.rows
    };
    let cmd = if cols > 80 { cols - 66 } else { 72 };
    (n.max(1), cmd.max(16))
}

/// iotop 风格的字节速率：B/s、K/s、M/s、G/s（1024 进制）。
fn fmt_bps(bps: f64) -> String {
    const UNITS: [&str; 5] = ["B", "K", "M", "G", "T"];
    let mut v = bps;
    let mut unit = 0usize;
    while v >= 1024.0 && unit < UNITS.len() - 1 {
        v /= 1024.0;
        unit += 1;
    }
    format!("{:.2} {}/s", v, UNITS[unit])
}

fn fmt_pct(pct: f64) -> String {
    format!("{:>6.2} %", pct)
}

/// 按字符边界截断到至多 n 个字符，超出时以 '~' 结尾。
fn truncate_chars(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('~');
        out
    }
}

/// 解析 /etc/passwd 内容，建立 uid → 用户名映射（每个 uid 取第一个名字）。
fn parse_passwd(content: &str) -> HashMap<u32, String> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() >= 3 {
            if let Ok(uid) = fields[2].parse::<u32>() {
                map.entry(uid).or_insert_with(|| fields[0].to_string());
            }
        }
    }
    map
}

fn load_passwd() -> HashMap<u32, String> {
    fs::read_to_string("/etc/passwd")
        .map(|c| parse_passwd(&c))
        .unwrap_or_default()
}

fn user_name(uid: u32, passwd: &HashMap<u32, String>, max_chars: usize) -> String {
    if uid == u32::MAX {
        "?".to_string()
    } else {
        passwd
            .get(&uid)
            .map(|n| truncate_chars(n, max_chars))
            .unwrap_or_else(|| uid.to_string())
    }
}

/// 展示用命令：有 cmdline 则截断展示，否则用 [线程名]（内核线程）。
fn cmd_of(ident: &Ident, width: usize) -> String {
    if ident.cmdline.is_empty() {
        format!("[{}]", ident.comm)
    } else {
        truncate_chars(&ident.cmdline, width)
    }
}

fn render(
    prev: &Scan,
    cur: &Scan,
    elapsed_s: f64,
    opts: &TopOptions,
    tty: bool,
    passwd: &HashMap<u32, String>,
    delayacct: bool,
) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if tty {
        // 光标回屏幕原点并清屏，实现整屏刷新（非 TTY 下顺序输出，便于重定向存档）
        let _ = write!(out, "\x1b[H\x1b[2J");
    }

    let (row_limit, cmd_width) = view_limits(opts, tty);
    let mut rows = diff(prev, cur, elapsed_s);
    order(&mut rows);

    let (mut total_r, mut total_w) = (0.0f64, 0.0f64);
    for r in &rows {
        total_r += r.read_bps;
        total_w += r.write_bps;
    }
    let (actual_r, actual_w) = actual_bps(prev, cur, elapsed_s);

    let _ = writeln!(
        out,
        "Total DISK READ : {:>13} | Total DISK WRITE: {:>13}",
        fmt_bps(total_r),
        fmt_bps(total_w)
    );
    let _ = writeln!(
        out,
        "Actual DISK READ: {:>13} | Actual DISK WRITE: {:>13}",
        fmt_bps(actual_r),
        fmt_bps(actual_w)
    );
    if !delayacct {
        let _ = writeln!(
            out,
            "（kernel.task_delayacct=0，IO% 与 SWAPIN 恒为 0；开启: echo 1 > /proc/sys/kernel/task_delayacct）"
        );
    }
    if cur.skipped > 0 {
        let _ = writeln!(
            out,
            "（另有 {} 个线程因退出或权限未纳入统计）",
            cur.skipped
        );
    }

    let id_col = if opts.per_process { "PID" } else { "TID" };
    let _ = writeln!(
        out,
        "{:>7} {:>4} {:<8} {:>11} {:>11} {:>8} {:>8}  COMMAND",
        id_col, "PRIO", "USER", "DISK READ", "DISK WRITE", "SWAPIN", "IO>"
    );

    let shown: Vec<&Row> = rows
        .iter()
        .filter(|r| {
            opts.show_idle
                || r.read_bps > 0.0
                || r.write_bps > 0.0
                || r.io_pct > 0.0
                || r.swapin_pct > 0.0
        })
        .take(row_limit)
        .collect();
    if shown.is_empty() {
        let _ = writeln!(
            out,
            "（本间隔内无 IO 活动的{}）",
            if opts.per_process { "进程" } else { "线程" }
        );
    }
    for r in shown {
        let _ = writeln!(
            out,
            "{:>7} {:>4} {:<8} {:>11} {:>11} {:>8} {:>8}  {}",
            r.ident.id,
            r.ident.prio,
            user_name(r.ident.uid, passwd, 8),
            fmt_bps(r.read_bps),
            fmt_bps(r.write_bps),
            fmt_pct(r.swapin_pct),
            fmt_pct(r.io_pct),
            cmd_of(&r.ident, cmd_width)
        );
    }
    let _ = out.flush();
}

pub fn run(opts: TopOptions) {
    let tty = io::stdout().is_terminal();
    let passwd = load_passwd();
    let delayacct = delayacct_enabled();
    let mut ts = taskstats::Taskstats::open();
    let mut prev = scan(opts.per_process, &mut ts);

    if !tty {
        println!(
            "iomon top —— 采样间隔 {}s{}，Ctrl+C 退出",
            opts.interval,
            opts.count.map(|c| format!("，共 {} 次", c)).unwrap_or_default()
        );
    }

    let mut printed: u64 = 0;
    loop {
        if let Some(c) = opts.count {
            if printed >= c {
                break;
            }
        }
        sleep(Duration::from_secs_f64(opts.interval));

        let cur = scan(opts.per_process, &mut ts);
        let elapsed = cur.at.duration_since(prev.at).as_secs_f64();
        render(&prev, &cur, elapsed, &opts, tty, &passwd, delayacct);
        prev = cur;
        printed += 1;
    }
}

/// 网页用的一行线程速率。
pub struct ProcRate {
    pub tid: u32,
    pub pid: u32,
    pub prio: String,
    pub user: String,
    pub read_bps: f64,
    pub write_bps: f64,
    pub swapin_pct: f64,
    pub io_pct: f64,
    pub command: String,
}

/// 两次采样之间的进程/线程 IO。第一帧还没有差值，`ready` 为 false。
pub struct IoFrame {
    pub ready: bool,
    pub elapsed_s: f64,
    pub delayacct: bool,
    pub skipped: usize,
    /// 配对成功的线程数（截断之前）
    pub threads: usize,
    pub total_read: f64,
    pub total_write: f64,
    pub actual_read: f64,
    pub actual_write: f64,
    pub rows: Vec<ProcRate>,
}

/// 给网页轮询用的采样器。内部保住上一帧和 taskstats 套接字。
pub struct ProcSampler {
    prev: Option<Scan>,
    ts: Option<Taskstats>,
    passwd: HashMap<u32, String>,
    delayacct: bool,
}

impl ProcSampler {
    pub fn open() -> Self {
        Self {
            prev: None,
            ts: Taskstats::open(),
            passwd: load_passwd(),
            delayacct: delayacct_enabled(),
        }
    }

    /// 再采一帧。返回按读写速率排序后的前 `limit` 行。
    pub fn poll(&mut self, limit: usize) -> IoFrame {
        let cur = scan(false, &mut self.ts);
        let Some(prev) = self.prev.as_ref() else {
            let skipped = cur.skipped;
            self.prev = Some(cur);
            return IoFrame {
                ready: false,
                elapsed_s: 0.0,
                delayacct: self.delayacct,
                skipped,
                threads: 0,
                total_read: 0.0,
                total_write: 0.0,
                actual_read: 0.0,
                actual_write: 0.0,
                rows: Vec::new(),
            };
        };
        let elapsed = cur.at.duration_since(prev.at).as_secs_f64().max(0.001);
        let mut rows = diff(prev, &cur, elapsed);
        order(&mut rows);
        let (mut total_read, mut total_write) = (0.0, 0.0);
        for row in &rows {
            total_read += row.read_bps;
            total_write += row.write_bps;
        }
        let (actual_read, actual_write) = actual_bps(prev, &cur, elapsed);
        let threads = rows.len();
        let skipped = cur.skipped;
        let rows = rows
            .into_iter()
            .take(limit)
            .map(|row| {
                let command = cmd_of(&row.ident, 240);
                let user = user_name(row.ident.uid, &self.passwd, 32);
                ProcRate {
                    tid: row.ident.id,
                    pid: row.ident.pid,
                    prio: row.ident.prio,
                    user,
                    read_bps: row.read_bps,
                    write_bps: row.write_bps,
                    swapin_pct: row.swapin_pct,
                    io_pct: row.io_pct,
                    command,
                }
            })
            .collect();
        self.prev = Some(cur);
        IoFrame {
            ready: true,
            elapsed_s: elapsed,
            delayacct: self.delayacct,
            skipped,
            threads,
            total_read,
            total_write,
            actual_read,
            actual_write,
            rows,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fmt_bps_units() {
        assert_eq!(fmt_bps(0.0), "0.00 B/s");
        assert_eq!(fmt_bps(999.99), "999.99 B/s");
        assert_eq!(fmt_bps(1024.0), "1.00 K/s");
        assert_eq!(fmt_bps(1536.0), "1.50 K/s");
        assert_eq!(fmt_bps(1024.0 * 1024.0 * 2.0), "2.00 M/s");
    }

    #[test]
    fn cmdline_formatting() {
        assert_eq!(fmt_cmdline(b"python3\0-x\0run\0"), "python3 -x run");
        assert_eq!(fmt_cmdline(b"a\0\0"), "a");
        assert_eq!(fmt_cmdline(b""), "");
    }

    #[test]
    fn passwd_parsing() {
        let m = parse_passwd(
            "root:x:0:0:root:/root:/bin/bash\n\
             www-data:x:33:33::/var/www:/usr/sbin/nologin\n\
             没有冒号的行\n",
        );
        assert_eq!(m.get(&0).unwrap(), "root");
        assert_eq!(m.get(&33).unwrap(), "www-data");
        assert!(!m.contains_key(&1));
    }

    #[test]
    fn truncate_keeps_char_boundary() {
        assert_eq!(truncate_chars("abcdef", 10), "abcdef");
        assert_eq!(truncate_chars("abcdef", 3), "ab~");
        // 多字节字符不应 panic 或截出半个字符
        assert_eq!(truncate_chars("中文测试", 3), "中文~");
    }

    fn ident(id: u32) -> Ident {
        Ident {
            id,
            pid: id,
            comm: format!("t{}", id),
            cmdline: String::new(),
            uid: 1000,
            prio: "be/4".to_string(),
        }
    }

    fn agg(
        read: u64,
        write: u64,
        cancel: u64,
        blkio_ns: u64,
        swapin_ns: u64,
        id: u32,
    ) -> (u32, Agg) {
        (
            id,
            Agg {
                read_bytes: read,
                write_bytes: write,
                cancelled_write_bytes: cancel,
                blkio_delay_ns: blkio_ns,
                swapin_delay_ns: swapin_ns,
                ident: ident(id),
            },
        )
    }

    fn scan_of(pairs: Vec<(u32, Agg)>) -> Scan {
        Scan {
            at: Instant::now(),
            aggs: pairs.into_iter().collect(),
            skipped: 0,
            vm_read: None,
            vm_write: None,
        }
    }

    #[test]
    fn diff_computes_rates_and_skips_new_entries() {
        let prev = scan_of(vec![agg(1000, 2000, 0, 100, 0, 10), agg(0, 0, 0, 0, 0, 20)]);
        let cur = scan_of(vec![
            agg(3000, 2000, 0, 100 + 250_000_000, 0, 10),
            agg(0, 500, 0, 0, 0, 20),
            agg(999, 999, 0, 9, 0, 30), // 只出现在 cur 中，应被跳过
        ]);
        let rows = diff(&prev, &cur, 2.0);
        assert_eq!(rows.len(), 2);
        let r10 = rows.iter().find(|r| r.ident.id == 10).unwrap();
        assert!((r10.read_bps - 1000.0).abs() < 1e-9);
        assert!((r10.write_bps - 0.0).abs() < 1e-9);
        // 2s 内新增 250ms 阻塞 → 12.5%
        assert!((r10.io_pct - 12.5).abs() < 1e-6);
        let r20 = rows.iter().find(|r| r.ident.id == 20).unwrap();
        assert!((r20.write_bps - 250.0).abs() < 1e-9);
    }

    #[test]
    fn diff_subtracts_cancelled_writes() {
        let prev = scan_of(vec![agg(0, 1000, 100, 0, 0, 1)]);
        let cur = scan_of(vec![agg(0, 3000, 500, 0, 0, 1)]);
        let rows = diff(&prev, &cur, 2.0);
        // 写增量 2000，取消增量 400，净写 1600 字节 / 2s = 800 B/s
        assert!((rows[0].write_bps - 800.0).abs() < 1e-9);
    }

    #[test]
    fn delay_pct_matches_iotop_and_caps_at_100() {
        // 1e7 ns = 10ms；1 秒里 1e9 ns → 100%
        assert!((delay_pct(1_000_000_000, 1.0) - 100.0).abs() < 1e-6);
        // 超过采样时长也封顶，iotop 不显示 150%
        assert!((delay_pct(3_000_000_000, 2.0) - 100.0).abs() < 1e-6);
        assert_eq!(delay_pct(1, 0.0), 0.0);
    }

    #[test]
    fn actual_uses_vmstat_delta() {
        let mut prev = scan_of(vec![]);
        let mut cur = scan_of(vec![]);
        prev.vm_read = Some(1024);
        prev.vm_write = Some(0);
        cur.vm_read = Some(1024 + 2048);
        cur.vm_write = Some(4096);
        let (r, w) = actual_bps(&prev, &cur, 2.0);
        assert!((r - 1024.0).abs() < 1e-9);
        assert!((w - 2048.0).abs() < 1e-9);
        // 任一侧缺失就不算速率，避免把累计值当成这一秒的增量
        cur.vm_read = None;
        assert_eq!(actual_bps(&prev, &cur, 2.0), (0.0, 0.0));
    }

    #[test]
    fn order_sorts_by_total_bandwidth() {
        let mut rows = vec![
            Row {
                read_bps: 100.0,
                write_bps: 0.0,
                swapin_pct: 0.0,
                io_pct: 0.0,
                ident: ident(1),
            },
            Row {
                read_bps: 50.0,
                write_bps: 60.0,
                swapin_pct: 0.0,
                io_pct: 0.0,
                ident: ident(2),
            },
            Row {
                read_bps: 0.0,
                write_bps: 0.0,
                swapin_pct: 0.0,
                io_pct: 90.0,
                ident: ident(3),
            },
        ];
        order(&mut rows);
        assert_eq!(rows[0].ident.id, 2); // 110 最大
        assert_eq!(rows[1].ident.id, 1); // 100
        assert_eq!(rows[2].ident.id, 3); // 零带宽沉底
    }
}
