//! 记下 IO 占比过高的进程，以及 7 天里的高峰。
//!
//! 某一秒超过阈值就记一条，不要求持续。连续超标会并成一段，避免同一进程每秒一条。
//! 记录按天写在磁盘上，超过 7 天的文件删掉。目录由环境变量 IOMON_DATA 指定。
//!
//! 时间有三种口径，职责如下（改动过期或分片逻辑前先看这里）：
//! - 记录时间戳（unix 秒）：episode/minute 的业务时间，内存 retain 与页面查询只看它；
//! - 文件名（UTC 天）：纯粹的物理分片名，不参与过期判断，与本地时区的「天」无关；
//! - 文件 mtime：唯一的过期判据。它不早于文件内任何一条记录的落盘时刻，
//!   因此含 7 天内数据的文件必然不会被 purge 误删。

use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use crate::json::{json_str, push_num};

const RETAIN_SECS: u64 = 7 * 24 * 3600;
const MAX_LIST: usize = 400;
const MAX_OFFENDERS: usize = 500;

#[derive(Clone)]
pub struct ProcSnap {
    pub pid: u32,
    pub user: String,
    pub command: String,
    pub io: f64,
    pub read: f64,
    pub write: f64,
}

struct Episode {
    pid: u32,
    user: String,
    command: String,
    start: u64,
    end: u64,
    samples: u32,
    over_s: f64,
    max_io: f64,
    last_io: f64,
    max_read: f64,
    max_write: f64,
    open: bool,
}

struct Offender {
    pid: u32,
    user: String,
    command: String,
    episodes: u32,
    samples: u32,
    over_s: f64,
    max_io: f64,
    max_read: f64,
    max_write: f64,
    last: u64,
}

#[derive(Clone)]
struct Minute {
    bucket: u64,
    max_io: f64,
    max_read: f64,
    max_write: f64,
    over: u32,
    top_io: f64,
    top_cmd: String,
    top_pid: u32,
}

pub struct AlertBook {
    pub threshold: f64,
    started: u64,
    samples: u64,
    alert_samples: u64,
    open: HashMap<u32, Episode>,
    closed: VecDeque<Episode>,
    offenders: HashMap<u32, Offender>,
    minutes: VecDeque<Minute>,
    dir: Option<PathBuf>,
    peak_io: f64,
    peak_io_at: u64,
    peak_io_cmd: String,
    peak_io_pid: u32,
    peak_write: f64,
    peak_write_at: u64,
    peak_read: f64,
    peak_read_at: u64,
}

impl AlertBook {
    pub fn new(threshold: f64, now: u64) -> Self {
        Self {
            threshold: clamp_threshold(threshold),
            started: now,
            samples: 0,
            alert_samples: 0,
            open: HashMap::new(),
            closed: VecDeque::new(),
            offenders: HashMap::new(),
            minutes: VecDeque::new(),
            dir: None,
            peak_io: 0.0,
            peak_io_at: 0,
            peak_io_cmd: String::new(),
            peak_io_pid: 0,
            peak_write: 0.0,
            peak_write_at: 0,
            peak_read: 0.0,
            peak_read_at: 0,
        }
    }

    pub fn open(dir: PathBuf, threshold: f64, now: u64) -> Self {
        let _ = fs::create_dir_all(dir.join("episodes"));
        let _ = fs::create_dir_all(dir.join("minutes"));
        let mut book = Self::new(threshold, now);
        book.dir = Some(dir);
        book.load_threshold();
        book.load_history(now);
        book.purge_files(now);
        book.retain(now);
        book
    }

    pub fn set_threshold(&mut self, value: f64) {
        let value = clamp_threshold(value);
        if (self.threshold - value).abs() < 1e-6 {
            return;
        }
        self.threshold = value;
        self.save_threshold();
    }

    pub fn open_count(&self) -> usize {
        self.open.len()
    }

    /// 吃进一帧已经按进程聚合过的快照。`actual_*` 是 vmstat 的落盘速率。
    pub fn ingest(&mut self, now: u64, elapsed_s: f64, actual_read: f64, actual_write: f64, procs: &[ProcSnap]) {
        self.samples = self.samples.saturating_add(1);
        let elapsed = if elapsed_s.is_finite() && elapsed_s > 0.0 {
            elapsed_s
        } else {
            1.0
        };

        if actual_write > self.peak_write {
            self.peak_write = actual_write;
            self.peak_write_at = now;
        }
        if actual_read > self.peak_read {
            self.peak_read = actual_read;
            self.peak_read_at = now;
        }

        let mut hottest_io = 0.0f64;
        let mut hottest_cmd = String::new();
        let mut hottest_pid = 0u32;
        for proc in procs {
            if proc.io > hottest_io {
                hottest_io = proc.io;
                hottest_cmd = proc.command.clone();
                hottest_pid = proc.pid;
            }
        }
        if hottest_io > self.peak_io {
            self.peak_io = hottest_io;
            self.peak_io_at = now;
            self.peak_io_cmd = hottest_cmd.clone();
            self.peak_io_pid = hottest_pid;
        }

        let mut over_now = Vec::new();
        for proc in procs {
            if proc.io + f64::EPSILON >= self.threshold {
                over_now.push(proc.pid);
                self.touch(now, elapsed, proc);
            }
        }
        if !over_now.is_empty() {
            self.alert_samples = self.alert_samples.saturating_add(1);
        }
        let still: std::collections::HashSet<u32> = over_now.into_iter().collect();
        let finished: Vec<u32> = self.open.keys().copied().filter(|pid| !still.contains(pid)).collect();
        for pid in finished {
            if let Some(mut ep) = self.open.remove(&pid) {
                ep.open = false;
                ep.end = now;
                self.save_episode(&ep);
                self.closed.push_front(ep);
            }
        }
        self.retain(now);
        self.trim_offenders();
        self.note_minute(now, hottest_io, hottest_cmd, hottest_pid, actual_read, actual_write, !still.is_empty());
    }

    fn touch(&mut self, now: u64, elapsed: f64, proc: &ProcSnap) {
        if let Some(ep) = self.open.get_mut(&proc.pid) {
            ep.end = now;
            ep.samples = ep.samples.saturating_add(1);
            ep.over_s += elapsed;
            ep.max_io = ep.max_io.max(proc.io);
            ep.last_io = proc.io;
            ep.max_read = ep.max_read.max(proc.read);
            ep.max_write = ep.max_write.max(proc.write);
            if !proc.command.is_empty() {
                ep.command = proc.command.clone();
            }
            ep.user = proc.user.clone();
        } else {
            self.open.insert(
                proc.pid,
                Episode {
                    pid: proc.pid,
                    user: proc.user.clone(),
                    command: proc.command.clone(),
                    start: now,
                    end: now,
                    samples: 1,
                    over_s: elapsed,
                    max_io: proc.io,
                    last_io: proc.io,
                    max_read: proc.read,
                    max_write: proc.write,
                    open: true,
                },
            );
            let off = self.offenders.entry(proc.pid).or_insert(Offender {
                pid: proc.pid,
                user: proc.user.clone(),
                command: proc.command.clone(),
                episodes: 0,
                samples: 0,
                over_s: 0.0,
                max_io: 0.0,
                max_read: 0.0,
                max_write: 0.0,
                last: now,
            });
            off.episodes = off.episodes.saturating_add(1);
        }
        if let Some(off) = self.offenders.get_mut(&proc.pid) {
            off.samples = off.samples.saturating_add(1);
            off.over_s += elapsed;
            off.max_io = off.max_io.max(proc.io);
            off.max_read = off.max_read.max(proc.read);
            off.max_write = off.max_write.max(proc.write);
            off.last = now;
            if !proc.command.is_empty() {
                off.command = proc.command.clone();
            }
            off.user = proc.user.clone();
        }
    }

    fn trim_offenders(&mut self) {
        if self.offenders.len() <= MAX_OFFENDERS + 8 {
            return;
        }
        let mut rank: Vec<(u32, f64, u32)> = self
            .offenders
            .values()
            .map(|o| (o.pid, o.max_io, o.samples))
            .collect();
        rank.sort_by(|a, b| b.1.total_cmp(&a.1).then(b.2.cmp(&a.2)));
        let keep: std::collections::HashSet<u32> = rank.into_iter().take(MAX_OFFENDERS).map(|x| x.0).collect();
        self.offenders.retain(|pid, _| keep.contains(pid) || self.open.contains_key(pid));
    }

    #[allow(clippy::too_many_arguments)] // 单次采样的记帐入参，打包成 struct 反而难读
    fn note_minute(&mut self, now: u64, top_io: f64, top_cmd: String, top_pid: u32, actual_read: f64, actual_write: f64, over: bool) {
        let bucket = now / 60;
        let same = self.minutes.back().map(|m| m.bucket == bucket).unwrap_or(false);
        if !same {
            self.minutes.push_back(Minute {
                bucket,
                max_io: 0.0,
                max_read: 0.0,
                max_write: 0.0,
                over: 0,
                top_io: 0.0,
                top_cmd: String::new(),
                top_pid: 0,
            });
            while self.minutes.len() > 7 * 24 * 60 {
                self.minutes.pop_front();
            }
        }
        let minute = self.minutes.back_mut().unwrap();
        let mut changed = false;
        if actual_read > minute.max_read {
            minute.max_read = actual_read;
            changed = true;
        }
        if actual_write > minute.max_write {
            minute.max_write = actual_write;
            changed = true;
        }
        if over {
            minute.over = minute.over.saturating_add(1);
            changed = true;
        }
        if top_io >= minute.max_io {
            minute.max_io = top_io;
            changed = true;
            if top_io > 0.0 {
                minute.top_io = top_io;
                minute.top_cmd = top_cmd;
                minute.top_pid = top_pid;
            }
        }
        if changed {
            let snap = minute.clone();
            self.save_minute(&snap);
        }
    }

    pub fn to_json(&self, delayacct: bool, host: &str, interval: f64, now: u64, from: u64, to: u64) -> String {
        let from = if from == 0 { now.saturating_sub(86400) } else { from };
        let to = if to <= from { now.saturating_add(1) } else { to };
        let overlaps = |start: u64, end: u64| start < to && end >= from;
        let mut episodes: Vec<&Episode> = self
            .open
            .values()
            .chain(self.closed.iter())
            .filter(|ep| overlaps(ep.start, ep.end))
            .collect();
        episodes.sort_by(|a, b| b.end.cmp(&a.end).then(b.max_io.total_cmp(&a.max_io)));
        let episode_total = episodes.len();
        let show_current = now >= from && now < to;
        let mut current: Vec<&Episode> = if show_current {
            self.open.values().collect()
        } else {
            Vec::new()
        };
        current.sort_by(|a, b| b.last_io.total_cmp(&a.last_io).then(a.pid.cmp(&b.pid)));

        let mut peak_io = 0.0f64;
        let mut peak_io_at = 0u64;
        let mut peak_io_pid = 0u32;
        let mut peak_io_cmd = String::new();
        let mut offenders: HashMap<u32, Offender> = HashMap::new();
        for ep in &episodes {
            if ep.max_io > peak_io {
                peak_io = ep.max_io;
                peak_io_at = ep.end;
                peak_io_pid = ep.pid;
                peak_io_cmd = ep.command.clone();
            }
            let off = offenders.entry(ep.pid).or_insert(Offender {
                pid: ep.pid,
                user: ep.user.clone(),
                command: ep.command.clone(),
                episodes: 0,
                samples: 0,
                over_s: 0.0,
                max_io: 0.0,
                max_read: 0.0,
                max_write: 0.0,
                last: ep.end,
            });
            off.episodes = off.episodes.saturating_add(1);
            off.samples = off.samples.saturating_add(ep.samples);
            off.over_s += ep.over_s;
            off.max_io = off.max_io.max(ep.max_io);
            off.max_read = off.max_read.max(ep.max_read);
            off.max_write = off.max_write.max(ep.max_write);
            if ep.end >= off.last {
                off.last = ep.end;
                if !ep.command.is_empty() {
                    off.command = ep.command.clone();
                }
                off.user = ep.user.clone();
            }
        }
        let mut offs: Vec<&Offender> = offenders.values().collect();
        offs.sort_by(|a, b| b.max_io.total_cmp(&a.max_io).then(b.episodes.cmp(&a.episodes)));

        let minutes: Vec<&Minute> = self
            .minutes
            .iter()
            .filter(|m| {
                let t = m.bucket * 60;
                t < to && t + 60 > from
            })
            .collect();
        let mut peak_write = 0.0f64;
        let mut peak_write_at = 0u64;
        let mut peak_read = 0.0f64;
        let mut peak_read_at = 0u64;
        for minute in &minutes {
            if minute.max_write > peak_write {
                peak_write = minute.max_write;
                peak_write_at = minute.bucket * 60;
            }
            if minute.max_read > peak_read {
                peak_read = minute.max_read;
                peak_read_at = minute.bucket * 60;
            }
        }

        let mut out = String::with_capacity(8192);
        out.push_str("{\"ok\":true,\"threshold\":");
        push_num(&mut out, self.threshold);
        out.push_str(",\"delayacct\":");
        out.push_str(if delayacct { "true" } else { "false" });
        out.push_str(",\"host\":");
        out.push_str(&json_str(host));
        out.push_str(",\"interval_s\":");
        push_num(&mut out, interval);
        out.push_str(",\"started\":");
        out.push_str(&self.started.to_string());
        out.push_str(",\"now\":");
        out.push_str(&now.to_string());
        out.push_str(",\"from\":");
        out.push_str(&from.to_string());
        out.push_str(",\"to\":");
        out.push_str(&to.to_string());
        out.push_str(",\"retain_days\":7,\"samples\":");
        out.push_str(&self.samples.to_string());
        out.push_str(",\"alert_samples\":");
        out.push_str(&self.alert_samples.to_string());
        out.push_str(",\"open\":");
        out.push_str(&current.len().to_string());
        out.push_str(",\"episode_total\":");
        out.push_str(&episode_total.to_string());
        out.push_str(",\"peak_io\":");
        push_num(&mut out, peak_io);
        out.push_str(",\"peak_io_at\":");
        out.push_str(&peak_io_at.to_string());
        out.push_str(",\"peak_io_pid\":");
        out.push_str(&peak_io_pid.to_string());
        out.push_str(",\"peak_io_cmd\":");
        out.push_str(&json_str(&peak_io_cmd));
        out.push_str(",\"peak_write\":");
        push_num(&mut out, peak_write);
        out.push_str(",\"peak_write_at\":");
        out.push_str(&peak_write_at.to_string());
        out.push_str(",\"peak_read\":");
        push_num(&mut out, peak_read);
        out.push_str(",\"peak_read_at\":");
        out.push_str(&peak_read_at.to_string());

        out.push_str(",\"current\":[");
        for (i, ep) in current.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_episode(&mut out, ep);
        }
        out.push_str("],\"episodes\":[");
        for (i, ep) in episodes.iter().take(MAX_LIST).enumerate() {
            if i > 0 {
                out.push(',');
            }
            push_episode(&mut out, ep);
        }
        out.push_str("],\"offenders\":[");
        for (i, off) in offs.iter().take(40).enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"pid\":");
            out.push_str(&off.pid.to_string());
            out.push_str(",\"user\":");
            out.push_str(&json_str(&off.user));
            out.push_str(",\"command\":");
            out.push_str(&json_str(&off.command));
            out.push_str(",\"episodes\":");
            out.push_str(&off.episodes.to_string());
            out.push_str(",\"samples\":");
            out.push_str(&off.samples.to_string());
            out.push_str(",\"over_s\":");
            push_num(&mut out, off.over_s);
            out.push_str(",\"max_io\":");
            push_num(&mut out, off.max_io);
            out.push_str(",\"max_read\":");
            push_num(&mut out, off.max_read);
            out.push_str(",\"max_write\":");
            push_num(&mut out, off.max_write);
            out.push_str(",\"last\":");
            out.push_str(&off.last.to_string());
            out.push('}');
        }
        out.push_str("],\"minutes\":[");
        for (i, minute) in minutes.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            out.push_str("{\"t\":");
            out.push_str(&(minute.bucket * 60).to_string());
            out.push_str(",\"max_io\":");
            push_num(&mut out, minute.max_io);
            out.push_str(",\"max_read\":");
            push_num(&mut out, minute.max_read);
            out.push_str(",\"max_write\":");
            push_num(&mut out, minute.max_write);
            out.push_str(",\"over\":");
            out.push_str(&minute.over.to_string());
            out.push_str(",\"top_io\":");
            push_num(&mut out, minute.top_io);
            out.push_str(",\"top_pid\":");
            out.push_str(&minute.top_pid.to_string());
            out.push_str(",\"top_cmd\":");
            out.push_str(&json_str(&minute.top_cmd));
            out.push('}');
        }
        out.push_str("]}");
        out
    }

    fn retain(&mut self, now: u64) {
        let cutoff = now.saturating_sub(RETAIN_SECS);
        self.closed.retain(|ep| ep.end >= cutoff);
        self.minutes.retain(|m| m.bucket.saturating_mul(60).saturating_add(60) > cutoff);
        self.purge_files(now);
    }

    fn save_episode(&self, ep: &Episode) {
        let Some(dir) = &self.dir else { return };
        let path = dir.join("episodes").join(format!("{}.jsonl", ymd(ep.end)));
        append_line(&path, &episode_line(ep));
    }

    fn save_minute(&self, minute: &Minute) {
        let Some(dir) = &self.dir else { return };
        let path = dir.join("minutes").join(format!("{}.jsonl", ymd(minute.bucket * 60)));
        append_line(&path, &minute_line(minute));
    }

    fn save_threshold(&self) {
        let Some(dir) = &self.dir else { return };
        let _ = fs::write(dir.join("threshold"), format!("{}\n", self.threshold));
    }

    fn load_threshold(&mut self) {
        let Some(dir) = &self.dir else { return };
        if let Ok(text) = fs::read_to_string(dir.join("threshold")) {
            if let Ok(value) = text.trim().parse::<f64>() {
                self.threshold = clamp_threshold(value);
            }
        }
    }

    fn load_history(&mut self, now: u64) {
        let Some(dir) = self.dir.clone() else { return };
        let cutoff = now.saturating_sub(RETAIN_SECS);
        if let Ok(rd) = fs::read_dir(dir.join("episodes")) {
            for entry in rd.flatten() {
                self.load_episode_file(&entry.path(), cutoff);
            }
        }
        let mut folded: HashMap<u64, Minute> = HashMap::new();
        if let Ok(rd) = fs::read_dir(dir.join("minutes")) {
            for entry in rd.flatten() {
                self.load_minute_file(&entry.path(), cutoff, &mut folded);
            }
        }
        let mut minutes: Vec<Minute> = folded.into_values().collect();
        minutes.sort_by_key(|m| m.bucket);
        self.minutes = minutes.into_iter().collect();
    }

    // map_while：读取中途出错时停止，而不是在 Err 上无限迭代
    fn load_episode_file(&mut self, path: &Path, cutoff: u64) {
        let Ok(file) = fs::File::open(path) else { return };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if let Some(ep) = parse_episode(&line) {
                if ep.end >= cutoff {
                    self.closed.push_back(ep);
                }
            }
        }
    }

    fn load_minute_file(&self, path: &Path, cutoff: u64, into: &mut HashMap<u64, Minute>) {
        let Ok(file) = fs::File::open(path) else { return };
        for line in BufReader::new(file).lines().map_while(Result::ok) {
            if let Some(minute) = parse_minute(&line) {
                if minute.bucket.saturating_mul(60).saturating_add(60) <= cutoff {
                    continue;
                }
                into.entry(minute.bucket)
                    .and_modify(|old| merge_minute(old, &minute))
                    .or_insert(minute);
            }
        }
    }

    fn purge_files(&self, now: u64) {
        let Some(dir) = &self.dir else { return };
        let cutoff = now.saturating_sub(RETAIN_SECS);
        for folder in ["episodes", "minutes"] {
            let Ok(rd) = fs::read_dir(dir.join(folder)) else { continue };
            for entry in rd.flatten() {
                // 按最后写入时间判断过期：文件名里的日期是 UTC 切的，
                // 和本地时区「保留 7 天」的语义会差几个小时
                let Ok(meta) = entry.metadata() else { continue };
                let modified = meta
                    .modified()
                    .ok()
                    .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                    .map(|d| d.as_secs())
                    .unwrap_or(u64::MAX);
                if modified < cutoff {
                    let _ = fs::remove_file(entry.path());
                }
            }
        }
    }
}

fn episode_line(ep: &Episode) -> String {
    let mut out = String::new();
    push_episode(&mut out, ep);
    out
}

fn minute_line(minute: &Minute) -> String {
    format!(
        "{{\"bucket\":{},\"max_io\":{:.4},\"max_read\":{:.4},\"max_write\":{:.4},\"over\":{},\"top_io\":{:.4},\"top_pid\":{},\"top_cmd\":{}}}",
        minute.bucket,
        finite(minute.max_io),
        finite(minute.max_read),
        finite(minute.max_write),
        minute.over,
        finite(minute.top_io),
        minute.top_pid,
        json_str(&minute.top_cmd)
    )
}

fn finite(n: f64) -> f64 {
    if n.is_finite() { n } else { 0.0 }
}

fn merge_minute(old: &mut Minute, new: &Minute) {
    if new.max_read > old.max_read {
        old.max_read = new.max_read;
    }
    if new.max_write > old.max_write {
        old.max_write = new.max_write;
    }
    old.over = old.over.max(new.over);
    if new.max_io >= old.max_io {
        old.max_io = new.max_io;
        if !new.top_cmd.is_empty() {
            old.top_io = new.top_io;
            old.top_cmd = new.top_cmd.clone();
            old.top_pid = new.top_pid;
        }
    }
}

fn append_line(path: &Path, line: &str) {
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "{line}");
    }
}

fn ymd(unix: u64) -> String {
    let (y, m, d) = civil_from_days((unix / 86400) as i64);
    format!("{y:04}-{m:02}-{d:02}")
}

fn civil_from_days(z: i64) -> (i32, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y as i32, m as u32, d as u32)
}

/// 一行落盘 JSON 解析出的键值对（json::parse_object 保证语法正确）。
/// 取值时类型对不上返回 None，整行由调用方丢弃。
struct Fields(Vec<(String, crate::json::Value)>);

impl Fields {
    fn new(line: &str) -> Option<Self> {
        Some(Self(crate::json::parse_object(line)?))
    }

    fn str(&self, key: &str) -> Option<String> {
        self.0.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
            crate::json::Value::Str(s) => Some(s.clone()),
            _ => None,
        })
    }

    fn num(&self, key: &str) -> Option<f64> {
        self.0.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
            crate::json::Value::Num(n) => Some(*n),
            _ => None,
        })
    }
}

fn parse_episode(line: &str) -> Option<Episode> {
    let f = Fields::new(line)?;
    Some(Episode {
        pid: f.num("pid")? as u32,
        user: f.str("user")?,
        command: f.str("command")?,
        start: f.num("start")? as u64,
        end: f.num("end")? as u64,
        samples: f.num("samples").map(|n| n as u32).unwrap_or(1),
        over_s: f.num("over_s").unwrap_or(1.0),
        max_io: f.num("max_io")?,
        last_io: f.num("last_io").unwrap_or(0.0),
        max_read: f.num("max_read").unwrap_or(0.0),
        max_write: f.num("max_write").unwrap_or(0.0),
        open: false,
    })
}

fn parse_minute(line: &str) -> Option<Minute> {
    let f = Fields::new(line)?;
    Some(Minute {
        bucket: f.num("bucket")? as u64,
        max_io: f.num("max_io").unwrap_or(0.0),
        max_read: f.num("max_read").unwrap_or(0.0),
        max_write: f.num("max_write").unwrap_or(0.0),
        over: f.num("over").map(|n| n as u32).unwrap_or(0),
        top_io: f.num("top_io").unwrap_or(0.0),
        top_cmd: f.str("top_cmd").unwrap_or_default(),
        top_pid: f.num("top_pid").map(|n| n as u32).unwrap_or(0),
    })
}


pub fn data_dir() -> PathBuf {
    std::env::var("IOMON_DATA")
        .map(PathBuf::from)
        .unwrap_or_else(|_| PathBuf::from("/var/lib/iomon"))
}

fn clamp_threshold(value: f64) -> f64 {
    if !value.is_finite() {
        return 20.0;
    }
    value.clamp(1.0, 100.0)
}

fn push_episode(out: &mut String, ep: &Episode) {
    out.push_str("{\"pid\":");
    out.push_str(&ep.pid.to_string());
    out.push_str(",\"user\":");
    out.push_str(&json_str(&ep.user));
    out.push_str(",\"command\":");
    out.push_str(&json_str(&ep.command));
    out.push_str(",\"start\":");
    out.push_str(&ep.start.to_string());
    out.push_str(",\"end\":");
    out.push_str(&ep.end.to_string());
    out.push_str(",\"open\":");
    out.push_str(if ep.open { "true" } else { "false" });
    out.push_str(",\"samples\":");
    out.push_str(&ep.samples.to_string());
    out.push_str(",\"over_s\":");
    push_num(out, ep.over_s);
    out.push_str(",\"max_io\":");
    push_num(out, ep.max_io);
    out.push_str(",\"last_io\":");
    push_num(out, ep.last_io);
    out.push_str(",\"max_read\":");
    push_num(out, ep.max_read);
    out.push_str(",\"max_write\":");
    push_num(out, ep.max_write);
    out.push('}');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(pid: u32, io: f64, write: f64) -> ProcSnap {
        ProcSnap {
            pid,
            user: "root".into(),
            command: format!("proc-{pid}"),
            io,
            read: 0.0,
            write,
        }
    }

    #[test]
    fn opens_and_closes_episode() {
        let mut book = AlertBook::new(20.0, 1_000);
        book.ingest(1_000, 1.0, 0.0, 100.0, &[snap(7, 40.0, 50.0)]);
        assert_eq!(book.open_count(), 1);
        assert_eq!(book.alert_samples, 1);
        book.ingest(1_002, 1.0, 0.0, 10.0, &[snap(7, 5.0, 1.0)]);
        assert_eq!(book.open_count(), 0);
        assert_eq!(book.closed.len(), 1);
        assert!((book.closed[0].max_io - 40.0).abs() < 1e-6);
        assert!((book.peak_write - 100.0).abs() < 1e-6);
    }

    #[test]
    fn minute_keeps_the_busiest_sample() {
        let mut book = AlertBook::new(20.0, 60);
        book.ingest(60, 1.0, 0.0, 10.0, &[snap(1, 30.0, 1.0)]);
        book.ingest(80, 1.0, 0.0, 90.0, &[snap(1, 10.0, 1.0)]);
        assert_eq!(book.minutes.len(), 1);
        assert!((book.minutes[0].max_io - 30.0).abs() < 1e-6);
        assert!((book.minutes[0].max_write - 90.0).abs() < 1e-6);
        assert_eq!(book.minutes[0].top_cmd, "proc-1");
    }

    #[test]
    fn one_second_spike_is_kept_on_disk() {
        let dir = std::env::temp_dir().join(format!("iomon-records-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let mut book = AlertBook::open(dir.clone(), 20.0, 1_700_000_000);
        book.ingest(1_700_000_000, 1.0, 0.0, 10.0, &[snap(9, 55.0, 80.0)]);
        book.ingest(1_700_000_001, 1.0, 0.0, 0.0, &[]);
        assert_eq!(book.open_count(), 0);
        let again = AlertBook::open(dir.clone(), 20.0, 1_700_000_010);
        assert_eq!(again.closed.len(), 1);
        assert!((again.closed[0].max_io - 55.0).abs() < 1e-6);
        assert_eq!(again.closed[0].samples, 1);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unix_day_is_utc_date() {
        assert_eq!(ymd(0), "1970-01-01");
    }

    #[test]
    fn purge_by_mtime_keeps_fresh_files() {
        let dir = std::env::temp_dir().join(format!("iomon-purge-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let now = 1_700_000_000u64;
        fs::create_dir_all(dir.join("episodes")).unwrap();
        // 新写入的文件（mtime 为当前真实时间）即使文件名是很久以前的日期也不该被删
        let stale_name = dir.join("episodes/2020-01-01.jsonl");
        fs::write(&stale_name, "{}\n").unwrap();
        // open() 内部会跑 purge：按 mtime 判断，刚写入的文件不该被删
        let _ = AlertBook::open(dir.clone(), 20.0, now);
        assert!(stale_name.exists());
        let _ = fs::remove_dir_all(&dir);
    }

    /// 落盘格式的不变量测试：episode/minute 经过 json_str 写出、
    /// json::parse_object + Fields 读回后逐字段相等。字段值故意选最恶劣的组合
    /// （引号、反斜杠、换行、控制字符、中文、以及长得像 `"pid":` 的伪字段）。
    /// 写端（push_episode/minute_line）与读端（parse_episode/parse_minute）任何一侧
    /// 改动导致不再对称，这个测试都会红。
    #[test]
    fn episode_and_minute_survive_disk_roundtrip() {
        let dir = std::env::temp_dir().join(format!("iomon-roundtrip-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let now = 1_700_000_000u64;
        let snap = ProcSnap {
            pid: 31415,
            user: "ro\"ot\\1000\n".into(),
            command: "py\"thon -c 'x = {\"pid\": 1}' 中文\u{1}换行\n".into(),
            io: 88.5,
            read: 4096.0,
            write: 1_048_576.0,
        };
        let mut book = AlertBook::open(dir.clone(), 20.0, now);
        book.ingest(now, 1.0, 2e6, 3e6, std::slice::from_ref(&snap));
        book.ingest(now + 1, 1.0, 0.0, 0.0, &[]); // 下一帧无超标，episode 关闭并落盘

        let again = AlertBook::open(dir.clone(), 20.0, now + 10);
        assert_eq!(again.closed.len(), 1);
        let ep = &again.closed[0];
        assert_eq!(ep.pid, 31415);
        assert_eq!(ep.user, "ro\"ot\\1000\n");
        assert_eq!(ep.command, "py\"thon -c 'x = {\"pid\": 1}' 中文\u{1}换行\n");
        assert_eq!(ep.start, now);
        assert_eq!(ep.end, now + 1);
        assert_eq!(ep.samples, 1);
        assert!((ep.over_s - 1.0).abs() < 1e-9);
        assert!((ep.max_io - 88.5).abs() < 1e-6);
        assert!((ep.last_io - 88.5).abs() < 1e-6);
        assert!((ep.max_read - 4096.0).abs() < 1e-9);
        assert!((ep.max_write - 1_048_576.0).abs() < 1e-9);

        // minute 走同一条 json_str/minute_line -> parse_minute 链路
        assert_eq!(again.minutes.len(), 1);
        let m = &again.minutes[0];
        assert_eq!(m.bucket, now / 60);
        assert_eq!(m.top_cmd, snap.command);
        assert_eq!(m.top_pid, 31415);
        assert!((m.max_io - 88.5).abs() < 1e-6);
        assert!((m.max_write - 3e6).abs() < 1.0);
        assert_eq!(m.over, 1);
        let _ = fs::remove_dir_all(&dir);
    }
}
