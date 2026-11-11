//! iotop 风格的进程/线程 IO 排行视图（`iomon top`）。
//!
//! 采样是三层门控的：成本随 IO 活动量伸缩，与全机线程数无关。
//!
//! - **L0 机器门**：/proc/diskstats 的读/写完成数与扇区数无任何变化 ⟹
//!   本周期全机没有任何块设备 IO 完成（含 O_DIRECT），直接发布全零帧，
//!   整个周期只花一次小文件读。
//! - **L1 进程门**：顶层 /proc/<pid>/io 是线程组聚合值，其中
//!   read/write/cancelled_write_bytes 是各线程同名单调计数器之和——
//!   和不变 ⟹ 每个加数都不变；再配合 taskstats 的 TGID 聚合延迟（同理），
//!   两项都有基线且完全相等 ⟹ 整个进程跳过，零精度损失。
//!   任何读失败、计数器回退、进程新现一律下钻（存疑即下钻）。
//! - **L2 线程下钻**：遍历 /proc/<pid>/task 读每线程 io 与 stat，
//!   taskstats 逐线程查询（与旧版相同的路径）。
//!
//! L1 跳过时聚合证据表明该进程所有线程计数都没动：基线值依然精确，
//! 因此直接刷新基线时间戳——恢复活动那一帧的速率仍是"最近一帧"的
//! 瞬时口径，与全量扫描一致。L0 全机静默帧不做任何 /proc 读取、没有
//! 证据，时间戳保持不动：其后第一帧的速率按跨静默期的真实经过时间
//! 平均（有界的一次性平滑）。
//!
//! 身份信息（comm/uid/cmdline/ioprio）不在采样期读取，渲染时只为被
//! 展示的行现读（每帧按 pid 去重）。因此 PRIO 保持每线程精确查询，
//! 且没有跨帧缓存带来的陈旧显示问题。

use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::{self, IsTerminal, Write};
use std::thread::sleep;
use std::time::{Duration, Instant};

use crate::diskstats::{self, DiskStats};
use crate::ioprio;
use crate::proc_io::{self, ProcIo, ProcStat};
use crate::syscall;
use crate::taskstats::{Delays, Taskstats};
use crate::vmstat;

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

// ---------------------------------------------------------------------------
// 门控与差值的纯函数（可单测，不碰 /proc）
// ---------------------------------------------------------------------------

/// 磁盘三计数器（read/write/cancelled_write_bytes），L1 门控的比较键。
/// 只取磁盘级计数：rchar/wchar 随任意 read()/write() 变化（含 page cache
/// 命中），而 top 视图不展示它们，不应触发下钻。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct DiskKey(u64, u64, u64);

impl DiskKey {
    fn of(io: &ProcIo) -> Self {
        DiskKey(io.read_bytes, io.write_bytes, io.cancelled_write_bytes)
    }
}

/// L1 门控判定：全部证据都在且完全相等才允许跳过；任何存疑（缺证据、
/// 计数器变化或回退、无 taskstats）都返回 false（下钻）。
fn gate_quiet(
    base_agg: Option<DiskKey>,
    cur_agg: Option<DiskKey>,
    base_tgid: Option<Delays>,
    cur_tgid: Option<Delays>,
    tgid_gate: bool,
) -> bool {
    // 无 taskstats 时延迟来自线程 stat 的 blkio tick，聚合层没有证据
    // 证明"延迟也没变"，宁可全量下钻（精确优先）。
    if !tgid_gate {
        return false;
    }
    match (base_agg, cur_agg, base_tgid, cur_tgid) {
        (Some(b), Some(c), Some(bd), Some(cd)) => b == c && bd == cd,
        _ => false,
    }
}

/// 每线程计数器基线（自启动累计，单调不减）。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct ThreadCounters {
    read_bytes: u64,
    write_bytes: u64,
    cancelled_write_bytes: u64,
    blkio_delay_ns: u64,
    swapin_delay_ns: u64,
}

/// 每线程差值 → (read_bps, write_bps, swapin_pct, io_pct)。
/// 写字节扣除 cancelled，与 iotop 相同；饱和减法防御计数器回退。
fn thread_row(base: &ThreadCounters, cur: &ThreadCounters, elapsed_s: f64) -> (f64, f64, f64, f64) {
    let write_delta = cur.write_bytes.saturating_sub(base.write_bytes);
    let cancel_delta = cur
        .cancelled_write_bytes
        .saturating_sub(base.cancelled_write_bytes);
    (
        cur.read_bytes.saturating_sub(base.read_bytes) as f64 / elapsed_s,
        write_delta.saturating_sub(cancel_delta) as f64 / elapsed_s,
        delay_pct(
            cur.swapin_delay_ns.saturating_sub(base.swapin_delay_ns),
            elapsed_s,
        ),
        delay_pct(
            cur.blkio_delay_ns.saturating_sub(base.blkio_delay_ns),
            elapsed_s,
        ),
    )
}

/// 延迟纳秒占采样时长的百分比。iotop 用 delta/(秒*1e7) 并封顶 100。
fn delay_pct(delta_ns: u64, elapsed_s: f64) -> f64 {
    // NaN 或非正的间隔都按 0 处理（等价于 !(elapsed_s > 0.0)），避免除出 inf。
    if elapsed_s.is_nan() || elapsed_s <= 0.0 {
        return 0.0;
    }
    (delta_ns as f64 / (elapsed_s * 10_000_000.0)).min(100.0)
}

/// vmstat 差值 → Actual 速率（B/s）。任一侧缺失就不算，避免把累计值当增量。
fn actual_rate(prev: Option<(u64, u64)>, cur: Option<(u64, u64)>, elapsed_s: f64) -> (f64, f64) {
    match (prev, cur) {
        (Some((pr, pw)), Some((cr, cw))) if elapsed_s > 0.0 => (
            cr.saturating_sub(pr) as f64 / elapsed_s,
            cw.saturating_sub(pw) as f64 / elapsed_s,
        ),
        _ => (0.0, 0.0),
    }
}

/// 一行速率（身份未解析，渲染期再补）。
pub struct RateRow {
    /// 线程视图为 TID；-P 聚合后为 PID
    pub id: u32,
    pub pid: u32,
    pub read_bps: f64,
    pub write_bps: f64,
    pub swapin_pct: f64,
    /// 本间隔阻塞在磁盘 IO 上的时间占比，最大 100（与 iotop 相同）
    pub io_pct: f64,
}

/// 按读写速率合计降序，其次 IO%、SWAPIN，最后按 ID 保证稳定。
fn order(rows: &mut [RateRow]) {
    rows.sort_by(|a, b| {
        (b.read_bps + b.write_bps)
            .total_cmp(&(a.read_bps + a.write_bps))
            .then_with(|| b.io_pct.total_cmp(&a.io_pct))
            .then_with(|| b.swapin_pct.total_cmp(&a.swapin_pct))
            .then_with(|| a.id.cmp(&b.id))
    });
}

/// -P 聚合（纯函数）：按 PID 合并线程行。速率为和；延迟占比对延迟
/// 增量是线性的，先求和再封顶与"对求和后的延迟算占比"等价。
fn aggregate_by_pid(rows: Vec<RateRow>) -> Vec<RateRow> {
    let mut by_pid: HashMap<u32, RateRow> = HashMap::new();
    for r in rows {
        let e = by_pid.entry(r.pid).or_insert(RateRow {
            id: r.pid,
            pid: r.pid,
            read_bps: 0.0,
            write_bps: 0.0,
            swapin_pct: 0.0,
            io_pct: 0.0,
        });
        e.read_bps += r.read_bps;
        e.write_bps += r.write_bps;
        e.swapin_pct = (e.swapin_pct + r.swapin_pct).min(100.0);
        e.io_pct = (e.io_pct + r.io_pct).min(100.0);
    }
    by_pid.into_values().collect()
}

// ---------------------------------------------------------------------------
// 有状态采样器：三层门控
// ---------------------------------------------------------------------------

/// 每进程采样状态：L1 门控基线 + 各线程基线 + 上次下钻时刻。
struct ProcEntry {
    at: Instant,
    /// 顶层聚合三计数器；读取失败为 None（None ⟹ 下帧必下钻）
    agg: Option<DiskKey>,
    /// TGID 聚合延迟基线；taskstats 不可用或查询失败为 None
    tgid: Option<Delays>,
    threads: HashMap<u32, ThreadCounters>,
}

/// 一帧采样结果。
pub struct RawFrame {
    /// 是否已有可配对的基线（第一帧只有基线没有差值）
    pub ready: bool,
    /// 帧节拍：两次 poll 的间隔。各行速率的分母是各自进程"上次下钻
    /// 至今"的真实时长，可能长于节拍（见模块注释的静默期语义）。
    pub elapsed_s: f64,
    pub delayacct: bool,
    /// 下钻时因进程退出或权限原因未能读取 io/stat 的线程数
    pub skipped: usize,
    /// 全部已知线程数（含静默跳过的）
    pub threads: usize,
    /// 本帧实际下钻读取的线程数（自观测：空闲时应为 0）
    pub threads_read: usize,
    /// 本帧 poll 耗时（毫秒，自观测）
    pub scan_ms: f64,
    pub total_read: f64,
    pub total_write: f64,
    /// Actual 吞吐（/proc/vmstat 的 pgpgin/pgpgout 差值，与 iotop 相同）
    pub actual_read: f64,
    pub actual_write: f64,
    pub rows: Vec<RateRow>,
}

pub struct ThreadScanner {
    ts: Option<Taskstats>,
    procs: HashMap<u32, ProcEntry>,
    /// L0 基线；首帧 None ⟹ 全量
    disks_prev: Option<Vec<DiskStats>>,
    /// vmstat 基线（每帧推进，供 Actual 差值）
    vm_prev: Option<(u64, u64)>,
    passwd: HashMap<u32, String>,
    delayacct: bool,
    last_frame: Option<Instant>,
}

impl ThreadScanner {
    pub fn open() -> Self {
        Self {
            ts: Taskstats::open(),
            procs: HashMap::new(),
            disks_prev: None,
            vm_prev: None,
            passwd: load_passwd(),
            delayacct: delayacct_enabled(),
            last_frame: None,
        }
    }

    pub fn passwd(&self) -> &HashMap<u32, String> {
        &self.passwd
    }

    /// 再采一帧。`per_process` 为 true 时行按 PID 聚合（-P）。
    pub fn poll(&mut self, per_process: bool) -> RawFrame {
        let started = Instant::now();
        let ts_active = self.ts.as_ref().is_some_and(|t| t.is_active());

        // L0 机器门：首帧或读取失败都视为"有活动"，走全量。
        let disks = diskstats::read().ok();
        let machine_quiet = match (&self.disks_prev, &disks) {
            (Some(p), Some(c)) => !diskstats::any_activity(p, c),
            _ => false,
        };
        self.disks_prev = disks;

        let mut rows: Vec<RateRow> = Vec::new();
        let mut skipped = 0usize;
        let mut threads_read = 0usize;
        let mut known_threads = 0usize;

        if machine_quiet {
            // 全零帧：不读任何 /proc/<pid>，不动任何基线。下一帧恢复
            // 活动时，差值会以真实经过时间摊回。
            for (&pid, entry) in &self.procs {
                for &tid in entry.threads.keys() {
                    rows.push(RateRow {
                        id: tid,
                        pid,
                        read_bps: 0.0,
                        write_bps: 0.0,
                        swapin_pct: 0.0,
                        io_pct: 0.0,
                    });
                }
                known_threads += entry.threads.len();
            }
        } else {
            let mut seen: HashSet<u32> = HashSet::new();
            for pid in list_numeric_dirs("/proc") {
                seen.insert(pid);
                let cur_agg = proc_io::read_proc_io(pid).ok().map(|io| DiskKey::of(&io));
                let cur_tgid = if ts_active {
                    self.ts.as_mut().and_then(|t| t.query_tgid(pid))
                } else {
                    None
                };

                let quiet = match self.procs.get(&pid) {
                    Some(e) => gate_quiet(e.agg, cur_agg, e.tgid, cur_tgid, ts_active),
                    None => false,
                };
                if quiet {
                    // 聚合证据表明该进程所有线程计数都没动：基线值依然精确，
                    // 刷新时间戳即可，恢复活动那帧回到最近一帧的瞬时口径。
                    let e = self.procs.get_mut(&pid).unwrap();
                    e.at = started;
                    for &tid in e.threads.keys() {
                        rows.push(RateRow {
                            id: tid,
                            pid,
                            read_bps: 0.0,
                            write_bps: 0.0,
                            swapin_pct: 0.0,
                            io_pct: 0.0,
                        });
                    }
                    known_threads += e.threads.len();
                    continue;
                }

                // L2 下钻：与旧版相同的线程级读取路径。
                let mut threads = HashMap::new();
                for tid in list_numeric_dirs(&format!("/proc/{}/task", pid)) {
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
                    let (blkio_ns, swapin_ns) = match self.ts.as_mut().and_then(|t| t.query(tid)) {
                        Some(d) => (d.blkio_ns, d.swapin_ns),
                        // 1 tick = 10ms = 10_000_000ns，与 taskstats 的纳秒对齐后再做差。
                        None => (stat.blkio_ticks.saturating_mul(10_000_000), 0),
                    };
                    threads.insert(
                        tid,
                        ThreadCounters {
                            read_bytes: io.read_bytes,
                            write_bytes: io.write_bytes,
                            cancelled_write_bytes: io.cancelled_write_bytes,
                            blkio_delay_ns: blkio_ns,
                            swapin_delay_ns: swapin_ns,
                        },
                    );
                    threads_read += 1;
                }
                known_threads += threads.len();

                // 与上次下钻的基线配对求差值。elapsed 用真实经过时间
                // （L1 跳过会刷新时间戳，正常情况下就是一帧的间隔）。
                if let Some(old) = self.procs.get(&pid) {
                    let elapsed = started.duration_since(old.at).as_secs_f64().max(0.001);
                    for (&tid, cur) in &threads {
                        if let Some(base) = old.threads.get(&tid) {
                            let (r, w, s, i) = thread_row(base, cur, elapsed);
                            rows.push(RateRow {
                                id: tid,
                                pid,
                                read_bps: r,
                                write_bps: w,
                                swapin_pct: s,
                                io_pct: i,
                            });
                        }
                    }
                }
                self.procs.insert(
                    pid,
                    ProcEntry {
                        at: started,
                        agg: cur_agg,
                        tgid: cur_tgid,
                        threads,
                    },
                );
            }
            self.procs.retain(|pid, _| seen.contains(pid));
        }

        if per_process {
            rows = aggregate_by_pid(rows);
        }
        order(&mut rows);
        let (mut total_read, mut total_write) = (0.0f64, 0.0f64);
        for r in &rows {
            total_read += r.read_bps;
            total_write += r.write_bps;
        }

        let elapsed_s = self
            .last_frame
            .map(|l| started.duration_since(l).as_secs_f64())
            .unwrap_or(0.0);
        let vm = vmstat::read();
        let (actual_read, actual_write) = actual_rate(self.vm_prev, vm, elapsed_s);
        if let Some(v) = vm {
            self.vm_prev = Some(v);
        }

        let ready = self.last_frame.is_some() && !self.procs.is_empty();
        let scan_ms = started.elapsed().as_secs_f64() * 1000.0;
        self.last_frame = Some(started);

        RawFrame {
            ready,
            elapsed_s,
            delayacct: self.delayacct,
            skipped,
            threads: known_threads,
            threads_read,
            scan_ms,
            total_read,
            total_write,
            actual_read,
            actual_write,
            rows,
        }
    }
}

// ---------------------------------------------------------------------------
// 渲染期身份解析（只为被展示的行读取 /proc）
// ---------------------------------------------------------------------------

/// 展示单元的身份信息。只在渲染期为被展示的行构造，不进采样状态。
#[derive(Clone)]
struct Ident {
    /// 线程级为 TID，进程级为 PID
    id: u32,
    /// 线程名（/proc/<tid>/stat 的 comm）
    comm: String,
    /// 已格式化的命令行；内核线程为空串
    cmdline: String,
    /// real uid；读取失败为 u32::MAX（显示为 "?"）
    uid: u32,
    /// iotop 风格的 IO 优先级，如 be/4、rt/4、idle
    prio: String,
}

/// 身份解析的读取函数集。默认接真实 /proc；测试注入计数桩验证去重。
pub struct ResolveFns {
    pub uid: fn(u32) -> Option<u32>,
    pub cmdline: fn(u32) -> String,
    pub stat: fn(u32, u32) -> Option<ProcStat>,
    pub ioprio: fn(u32, i64, u32) -> String,
}

fn fs_cmdline(pid: u32) -> String {
    fmt_cmdline(&fs::read(format!("/proc/{}/cmdline", pid)).unwrap_or_default())
}

fn fs_thread_stat(pid: u32, tid: u32) -> Option<ProcStat> {
    proc_io::read_thread_stat(pid, tid).ok()
}

pub fn fs_resolve() -> ResolveFns {
    ResolveFns {
        uid: read_uid,
        cmdline: fs_cmdline,
        stat: fs_thread_stat,
        ioprio: ioprio::read_ioprio,
    }
}

/// 为将被展示的行解析身份。同一 pid 的 status/cmdline 每帧只读一次；
/// stat 与 ioprio 每行读自己的（PRIO 因此保持每线程精确）。
/// 读取失败与旧版一致：uid 与 PRIO 显示 "?"。
fn resolve_idents(rows: &[&RateRow], fns: &ResolveFns) -> Vec<Ident> {
    let mut uids: HashMap<u32, Option<u32>> = HashMap::new();
    let mut cmdlines: HashMap<u32, String> = HashMap::new();
    rows.iter()
        .map(|r| {
            let uid = *uids.entry(r.pid).or_insert_with(|| (fns.uid)(r.pid));
            let cmdline = cmdlines
                .entry(r.pid)
                .or_insert_with(|| (fns.cmdline)(r.pid));
            let (comm, prio) = match (fns.stat)(r.pid, r.id) {
                Some(s) => (s.comm.clone(), (fns.ioprio)(r.id, s.nice, s.policy)),
                None => (String::new(), "?".to_string()),
            };
            Ident {
                id: r.id,
                comm,
                cmdline: cmdline.clone(),
                uid: uid.unwrap_or(u32::MAX),
                prio,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// CLI 渲染
// ---------------------------------------------------------------------------

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

fn render(frame: &RawFrame, opts: &TopOptions, tty: bool, passwd: &HashMap<u32, String>) {
    let stdout = io::stdout();
    let mut out = stdout.lock();
    if tty {
        // 光标回屏幕原点并清屏，实现整屏刷新（非 TTY 下顺序输出，便于重定向存档）
        let _ = write!(out, "\x1b[H\x1b[2J");
    }

    // 先过滤截断，再为将被展示的行解析身份（渲染期读取 /proc）。
    let (row_limit, cmd_width) = view_limits(opts, tty);
    let shown: Vec<&RateRow> = frame
        .rows
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
    let idents = resolve_idents(&shown, &fs_resolve());

    let _ = writeln!(
        out,
        "Total DISK READ : {:>13} | Total DISK WRITE: {:>13}",
        fmt_bps(frame.total_read),
        fmt_bps(frame.total_write)
    );
    let _ = writeln!(
        out,
        "Actual DISK READ: {:>13} | Actual DISK WRITE: {:>13}",
        fmt_bps(frame.actual_read),
        fmt_bps(frame.actual_write)
    );
    if !frame.delayacct {
        let _ = writeln!(
            out,
            "（kernel.task_delayacct=0，IO% 与 SWAPIN 恒为 0；开启: echo 1 > /proc/sys/kernel/task_delayacct）"
        );
    }
    if frame.skipped > 0 {
        let _ = writeln!(
            out,
            "（另有 {} 个线程因退出或权限未纳入统计）",
            frame.skipped
        );
    }

    let id_col = if opts.per_process { "PID" } else { "TID" };
    let _ = writeln!(
        out,
        "{:>7} {:>4} {:<8} {:>11} {:>11} {:>8} {:>8}  COMMAND",
        id_col, "PRIO", "USER", "DISK READ", "DISK WRITE", "SWAPIN", "IO>"
    );

    if shown.is_empty() {
        let _ = writeln!(
            out,
            "（本间隔内无 IO 活动的{}）",
            if opts.per_process { "进程" } else { "线程" }
        );
    }
    for (r, id) in shown.iter().zip(&idents) {
        let _ = writeln!(
            out,
            "{:>7} {:>4} {:<8} {:>11} {:>11} {:>8} {:>8}  {}",
            id.id,
            id.prio,
            user_name(id.uid, passwd, 8),
            fmt_bps(r.read_bps),
            fmt_bps(r.write_bps),
            fmt_pct(r.swapin_pct),
            fmt_pct(r.io_pct),
            cmd_of(id, cmd_width)
        );
    }
    let _ = out.flush();
}

pub fn run(opts: TopOptions) {
    let tty = io::stdout().is_terminal();
    let mut scanner = ThreadScanner::open();

    if !tty {
        println!(
            "iomon top —— 采样间隔 {}s{}，Ctrl+C 退出",
            opts.interval,
            opts
                .count
                .map(|c| format!("，共 {} 次", c))
                .unwrap_or_default()
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

        let frame = scanner.poll(opts.per_process);
        render(&frame, &opts, tty, scanner.passwd());
        printed += 1;
    }
}

// ---------------------------------------------------------------------------
// web 展示行
// ---------------------------------------------------------------------------

/// 网页用的一行线程速率（身份已在渲染期解析完毕）。
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

/// web 展示行：排序后前 `limit` 行 + 身份解析（渲染期读取）。
pub fn display_rates(
    frame: &RawFrame,
    limit: usize,
    passwd: &HashMap<u32, String>,
) -> Vec<ProcRate> {
    let shown: Vec<&RateRow> = frame.rows.iter().take(limit).collect();
    let idents = resolve_idents(&shown, &fs_resolve());
    shown
        .iter()
        .zip(idents)
        .map(|(r, id)| ProcRate {
            tid: r.id,
            pid: r.pid,
            prio: id.prio.clone(),
            user: user_name(id.uid, passwd, 32),
            read_bps: r.read_bps,
            write_bps: r.write_bps,
            swapin_pct: r.swapin_pct,
            io_pct: r.io_pct,
            command: cmd_of(&id, 240),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn counters(
        read: u64,
        write: u64,
        cancel: u64,
        blkio_ns: u64,
        swapin_ns: u64,
    ) -> ThreadCounters {
        ThreadCounters {
            read_bytes: read,
            write_bytes: write,
            cancelled_write_bytes: cancel,
            blkio_delay_ns: blkio_ns,
            swapin_delay_ns: swapin_ns,
        }
    }

    fn row(id: u32, read: f64, write: f64) -> RateRow {
        RateRow {
            id,
            pid: id,
            read_bps: read,
            write_bps: write,
            swapin_pct: 0.0,
            io_pct: 0.0,
        }
    }

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

    #[test]
    fn gate_skips_only_with_full_evidence() {
        let agg = DiskKey(1, 2, 3);
        let d = Delays {
            blkio_ns: 10,
            swapin_ns: 20,
        };
        assert!(gate_quiet(Some(agg), Some(agg), Some(d), Some(d), true));
    }

    #[test]
    fn gate_descends_when_disk_counters_change() {
        let d = Delays {
            blkio_ns: 10,
            swapin_ns: 20,
        };
        // 增加或回退（减小）都视为变化
        assert!(!gate_quiet(
            Some(DiskKey(1, 2, 3)),
            Some(DiskKey(2, 2, 3)),
            Some(d),
            Some(d),
            true
        ));
        assert!(!gate_quiet(
            Some(DiskKey(1, 2, 3)),
            Some(DiskKey(0, 2, 3)),
            Some(d),
            Some(d),
            true
        ));
    }

    #[test]
    fn gate_ignores_rchar_only_changes() {
        // DiskKey 只含磁盘三计数器：rchar/wchar 的变化根本不进入比较，
        // page cache 命中不会触发下钻。
        let d = Delays {
            blkio_ns: 10,
            swapin_ns: 20,
        };
        assert!(gate_quiet(
            Some(DiskKey(7, 8, 9)),
            Some(DiskKey(7, 8, 9)),
            Some(d),
            Some(d),
            true
        ));
    }

    #[test]
    fn gate_descends_when_tgid_delay_changes() {
        let agg = DiskKey(1, 2, 3);
        assert!(!gate_quiet(
            Some(agg),
            Some(agg),
            Some(Delays {
                blkio_ns: 10,
                swapin_ns: 20
            }),
            Some(Delays {
                blkio_ns: 25,
                swapin_ns: 20
            }),
            true
        ));
    }

    #[test]
    fn gate_descends_without_taskstats_or_missing_evidence() {
        let agg = Some(DiskKey(1, 2, 3));
        let d = Delays {
            blkio_ns: 10,
            swapin_ns: 20,
        };
        // 无 taskstats：永远下钻
        assert!(!gate_quiet(agg, agg, Some(d), Some(d), false));
        // 任一侧证据缺失：下钻
        assert!(!gate_quiet(None, agg, Some(d), Some(d), true));
        assert!(!gate_quiet(agg, None, Some(d), Some(d), true));
        assert!(!gate_quiet(agg, agg, None, Some(d), true));
        assert!(!gate_quiet(agg, agg, Some(d), None, true));
    }

    #[test]
    fn thread_row_computes_rates_and_delays() {
        let base = counters(1000, 2000, 0, 100, 0);
        let cur = counters(3000, 2000, 0, 100 + 250_000_000, 0);
        let (r, w, s, i) = thread_row(&base, &cur, 2.0);
        assert!((r - 1000.0).abs() < 1e-9);
        assert!((w - 0.0).abs() < 1e-9);
        assert!((s - 0.0).abs() < 1e-9);
        // 2s 内新增 250ms 阻塞 → 12.5%
        assert!((i - 12.5).abs() < 1e-6);
    }

    #[test]
    fn thread_row_subtracts_cancelled_writes() {
        let base = counters(0, 1000, 100, 0, 0);
        let cur = counters(0, 3000, 500, 0, 0);
        let (r, w, _, _) = thread_row(&base, &cur, 2.0);
        assert!((r - 0.0).abs() < 1e-9);
        // 写增量 2000，取消增量 400，净写 1600 字节 / 2s = 800 B/s
        assert!((w - 800.0).abs() < 1e-9);
    }

    #[test]
    fn thread_row_spans_quiet_gap_with_real_elapsed() {
        // 静默跳过若干帧后恢复活动：差值跨 3 秒计算，速率是真实平均值。
        let base = counters(0, 0, 0, 0, 0);
        let cur = counters(3000, 0, 0, 0, 0);
        let (r, _, _, _) = thread_row(&base, &cur, 3.0);
        assert!((r - 1000.0).abs() < 1e-9);
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
        let (r, w) = actual_rate(Some((1024, 0)), Some((1024 + 2048, 4096)), 2.0);
        assert!((r - 1024.0).abs() < 1e-9);
        assert!((w - 2048.0).abs() < 1e-9);
        // 任一侧缺失就不算速率，避免把累计值当成这一秒的增量
        assert_eq!(actual_rate(None, Some((1024, 0)), 1.0), (0.0, 0.0));
        assert_eq!(actual_rate(Some((0, 0)), None, 1.0), (0.0, 0.0));
    }

    #[test]
    fn order_sorts_by_total_bandwidth() {
        let mut rows = vec![
            row(1, 100.0, 0.0),
            row(2, 50.0, 60.0),
            RateRow {
                id: 3,
                pid: 3,
                read_bps: 0.0,
                write_bps: 0.0,
                swapin_pct: 0.0,
                io_pct: 90.0,
            },
        ];
        order(&mut rows);
        assert_eq!(rows[0].id, 2); // 110 最大
        assert_eq!(rows[1].id, 1); // 100
        assert_eq!(rows[2].id, 3); // 零带宽沉底
    }

    #[test]
    fn aggregate_by_pid_sums_and_clamps() {
        // 延迟占比对增量线性：先求和再封顶 = 先算占比再求和后封顶
        let rows = vec![
            RateRow {
                id: 11,
                pid: 1,
                read_bps: 100.0,
                write_bps: 0.0,
                swapin_pct: 0.0,
                io_pct: 30.0,
            },
            RateRow {
                id: 12,
                pid: 1,
                read_bps: 0.0,
                write_bps: 50.0,
                swapin_pct: 10.0,
                io_pct: 80.0,
            },
            RateRow {
                id: 20,
                pid: 2,
                read_bps: 0.0,
                write_bps: 1.0,
                swapin_pct: 0.0,
                io_pct: 0.0,
            },
        ];
        let mut agg = aggregate_by_pid(rows);
        order(&mut agg);
        assert_eq!(agg[0].id, 1);
        assert!((agg[0].read_bps - 100.0).abs() < 1e-9);
        assert!((agg[0].write_bps - 50.0).abs() < 1e-9);
        assert!((agg[0].io_pct - 100.0).abs() < 1e-9); // 30+80 封顶
        assert!((agg[0].swapin_pct - 10.0).abs() < 1e-9);
        assert_eq!(agg[1].id, 2);
    }

    #[test]
    fn resolve_reads_each_pid_once_and_per_row_stat() {
        static UID_CALLS: AtomicUsize = AtomicUsize::new(0);
        static CMD_CALLS: AtomicUsize = AtomicUsize::new(0);
        static STAT_CALLS: AtomicUsize = AtomicUsize::new(0);
        UID_CALLS.store(0, Ordering::SeqCst);
        CMD_CALLS.store(0, Ordering::SeqCst);
        STAT_CALLS.store(0, Ordering::SeqCst);

        fn uid(_pid: u32) -> Option<u32> {
            UID_CALLS.fetch_add(1, Ordering::SeqCst);
            Some(1000)
        }
        fn cmdline(_pid: u32) -> String {
            CMD_CALLS.fetch_add(1, Ordering::SeqCst);
            "java -Xmx4g app".to_string()
        }
        fn stat(_pid: u32, tid: u32) -> Option<ProcStat> {
            STAT_CALLS.fetch_add(1, Ordering::SeqCst);
            Some(ProcStat {
                comm: format!("t{}", tid),
                nice: 0,
                rt_priority: 0,
                policy: 0,
                blkio_ticks: 0,
            })
        }
        fn ioprio(_tid: u32, _nice: i64, _policy: u32) -> String {
            "be/4".to_string()
        }

        let fns = ResolveFns {
            uid,
            cmdline,
            stat,
            ioprio,
        };
        let r1 = RateRow {
            id: 11,
            pid: 1,
            read_bps: 1.0,
            write_bps: 0.0,
            swapin_pct: 0.0,
            io_pct: 0.0,
        };
        let r2 = RateRow {
            id: 12,
            pid: 1,
            read_bps: 0.0,
            write_bps: 2.0,
            swapin_pct: 0.0,
            io_pct: 0.0,
        };
        let idents = resolve_idents(&[&r1, &r2], &fns);
        // 同 pid 两行：status/cmdline 只读一次，stat 每行一次
        assert_eq!(UID_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(CMD_CALLS.load(Ordering::SeqCst), 1);
        assert_eq!(STAT_CALLS.load(Ordering::SeqCst), 2);
        assert_eq!(idents[0].uid, 1000);
        assert_eq!(idents[0].comm, "t11");
        assert_eq!(idents[0].prio, "be/4");
        assert_eq!(idents[1].comm, "t12");
    }

    #[test]
    fn resolve_marks_missing_identity() {
        fn uid(_pid: u32) -> Option<u32> {
            None
        }
        fn cmdline(_pid: u32) -> String {
            String::new()
        }
        fn stat(_pid: u32, _tid: u32) -> Option<ProcStat> {
            None
        }
        fn ioprio(_tid: u32, _nice: i64, _policy: u32) -> String {
            unreachable!("stat 读取失败时不会调 ioprio")
        }
        let fns = ResolveFns {
            uid,
            cmdline,
            stat,
            ioprio,
        };
        let r = RateRow {
            id: 5,
            pid: 5,
            read_bps: 0.0,
            write_bps: 0.0,
            swapin_pct: 0.0,
            io_pct: 0.0,
        };
        let idents = resolve_idents(&[&r], &fns);
        assert_eq!(idents[0].uid, u32::MAX); // 显示为 "?"
        assert_eq!(idents[0].prio, "?");
        assert_eq!(idents[0].comm, "");
        // cmdline 与 comm 都为空：cmd_of 退化为 "[]"，与旧版一致地丑但不崩
        assert_eq!(cmd_of(&idents[0], 40), "[]");
    }
}
