//! /proc/<pid>/io 与 /proc/<pid>/stat（iodelay）解析。

use std::fs;
use std::io;

/// /proc/<pid>/io 的累计计数（自进程启动起）。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcIo {
    /// read()/recv() 等返回的字节数（包含 page cache 命中部分）
    pub rchar: u64,
    pub wchar: u64,
    /// 读/写系统调用次数
    pub syscr: u64,
    pub syscw: u64,
    /// 真正下发到存储层的读/写字节数（不含 cache 命中）
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub cancelled_write_bytes: u64,
}

pub fn parse(content: &str) -> Result<ProcIo, String> {
    let mut io = ProcIo::default();
    let mut seen = 0usize;
    for line in content.lines() {
        let mut parts = line.splitn(2, ':');
        let key = match parts.next() {
            Some(k) => k.trim(),
            None => continue,
        };
        let value = match parts.next() {
            Some(v) => v.trim(),
            None => continue,
        };
        let slot = match key {
            "rchar" => Some(&mut io.rchar),
            "wchar" => Some(&mut io.wchar),
            "syscr" => Some(&mut io.syscr),
            "syscw" => Some(&mut io.syscw),
            "read_bytes" => Some(&mut io.read_bytes),
            "write_bytes" => Some(&mut io.write_bytes),
            "cancelled_write_bytes" => Some(&mut io.cancelled_write_bytes),
            _ => None,
        };
        // 未知字段（未来内核新增）直接跳过，不参与校验
        let slot = match slot {
            Some(s) => s,
            None => continue,
        };
        let n: u64 = value
            .parse()
            .map_err(|_| format!("字段 \"{}\" 的值无效: \"{}\"", key, value))?;
        *slot = n;
        seen += 1;
    }
    if seen < 7 {
        return Err(format!("字段不全: 仅识别到 {} 个（期望 7 个）", seen));
    }
    Ok(io)
}

/// 读取指定进程的 /proc/<pid>/io（即整个线程组的聚合计数）。
/// 读取其他用户进程需要相应权限（同 UID 或 root），否则返回 PermissionDenied。
pub fn read_proc_io(pid: u32) -> io::Result<ProcIo> {
    let content = fs::read_to_string(format!("/proc/{}/io", pid))?;
    parse(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// 读取单个线程自己的计数：/proc/<pid>/task/<tid>/io。
/// 注意顶层 /proc/<tid>/io 返回的其实是线程组聚合值，不能用于线程级监控。
pub fn read_thread_io(pid: u32, tid: u32) -> io::Result<ProcIo> {
    let content = fs::read_to_string(format!("/proc/{}/task/{}/io", pid, tid))?;
    parse(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// /proc/<pid>/stat 中与本工具相关的字段。
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ProcStat {
    /// 线程名（stat 第 2 字段，去括号）
    pub comm: String,
    /// nice 值（第 19 字段，可为负）
    pub nice: i64,
    /// 实时调度优先级（第 40 字段，非实时调度时为 0）
    pub rt_priority: u64,
    /// 调度策略（第 41 字段：0=normal，1=FIFO，2=RR，3=batch，5=idle）
    pub policy: u32,
    /// 累计阻塞在磁盘 IO 上的 clock tick（第 42 字段 delayacct_blkio_ticks）。
    /// USER_HZ 为 100，1 tick = 10ms，不是毫秒。
    pub blkio_ticks: u64,
}

/// 解析 /proc/<pid>/stat 内容。
/// comm（第 2 字段）带括号且可含空格，因此以第一个 '(' 与最后一个 ')' 为界
/// 跳过 pid 与 comm；tail 从第 3 字段（state）开始，字段下标 = 字段号 - 3。
pub fn parse_stat(content: &str) -> io::Result<ProcStat> {
    let open = content
        .find('(')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat 内容中没有 '('"))?;
    let close = content
        .rfind(')')
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "stat 内容中没有 ')'"))?;
    let fields: Vec<&str> = content[close + 1..].split_whitespace().collect();
    if fields.len() <= 39 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("stat 字段数不足: {}", fields.len() + 2),
        ));
    }
    let bad = |what: &str| io::Error::new(io::ErrorKind::InvalidData, format!("{} 不是有效数字", what));
    Ok(ProcStat {
        comm: content[open + 1..close].to_string(),
        // nice（19）、rt_priority（40）、policy（41）、blkio_ticks（42）
        nice: fields[16].parse().map_err(|_| bad("nice"))?,
        rt_priority: fields[37].parse().map_err(|_| bad("rt_priority"))?,
        policy: fields[38].parse().map_err(|_| bad("policy"))?,
        blkio_ticks: fields[39].parse().map_err(|_| bad("blkio_ticks"))?,
    })
}

/// 读取指定线程的 /proc/<tid>/stat（对线程组 leader 而言就是进程视角）。
pub fn read_stat(pid: u32) -> io::Result<ProcStat> {
    let content = fs::read_to_string(format!("/proc/{}/stat", pid))?;
    parse_stat(&content)
}

/// 读取单个线程自己的 /proc/<pid>/task/<tid>/stat。
pub fn read_thread_stat(pid: u32, tid: u32) -> io::Result<ProcStat> {
    let content = fs::read_to_string(format!("/proc/{}/task/{}/stat", pid, tid))?;
    parse_stat(&content)
}

/// 一个采样间隔内的进程 IO 速率。
pub struct ProcIoRate {
    pub rchar_s: f64,
    pub wchar_s: f64,
    /// 真实磁盘读/写速率（KiB/s）
    pub read_kbps: f64,
    pub write_kbps: f64,
    /// 本间隔新增的 IO 等待时间（毫秒）。由 blkio tick × 10 换算。
    pub iodelay_ms: u64,
}

pub fn rate(
    prev: &ProcIo,
    prev_ticks: u64,
    cur: &ProcIo,
    cur_ticks: u64,
    elapsed_s: f64,
) -> ProcIoRate {
    ProcIoRate {
        rchar_s: cur.rchar.saturating_sub(prev.rchar) as f64 / elapsed_s,
        wchar_s: cur.wchar.saturating_sub(prev.wchar) as f64 / elapsed_s,
        read_kbps: cur.read_bytes.saturating_sub(prev.read_bytes) as f64 / 1024.0 / elapsed_s,
        write_kbps: cur.write_bytes.saturating_sub(prev.write_bytes) as f64 / 1024.0 / elapsed_s,
        iodelay_ms: cur_ticks.saturating_sub(prev_ticks).saturating_mul(10),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "\
rchar: 486725774
wchar: 179979190
syscr: 45297
syscw: 16532
read_bytes: 23859200
write_bytes: 10539008
cancelled_write_bytes: 0
";

    #[test]
    fn parse_proc_io_sample() {
        let io = parse(SAMPLE).expect("解析应成功");
        assert_eq!(io.rchar, 486725774);
        assert_eq!(io.wchar, 179979190);
        assert_eq!(io.syscr, 45297);
        assert_eq!(io.syscw, 16532);
        assert_eq!(io.read_bytes, 23859200);
        assert_eq!(io.write_bytes, 10539008);
        assert_eq!(io.cancelled_write_bytes, 0);
    }

    #[test]
    fn parse_rejects_missing_fields() {
        assert!(parse("rchar: 100\nwchar: 200\n").is_err());
    }

    /// 构造一条 /proc/<pid>/stat：第 3 字段为 state，第 4~41 字段值等于字段号，
    /// nice 可指定，第 42 字段（blkio_ticks）为 42。
    fn make_stat(comm: &str, nice: &str) -> String {
        let mut fields: Vec<String> = vec!["S".to_string()];
        for i in 4..=41 {
            fields.push(i.to_string());
        }
        fields[16] = nice.to_string(); // nice 是第 19 字段 → 下标 16
        fields.push("42".to_string());
        format!("123 ({}) {}", comm, fields.join(" "))
    }

    #[test]
    fn parse_stat_sample() {
        let s = parse_stat(&make_stat("test proc", "19")).unwrap();
        assert_eq!(s.comm, "test proc");
        assert_eq!(s.nice, 19);
        assert_eq!(s.rt_priority, 40);
        assert_eq!(s.policy, 41);
        assert_eq!(s.blkio_ticks, 42);

        // comm 含空格也应正确定位
        let s2 = parse_stat(&make_stat("my test proc", "0")).unwrap();
        assert_eq!(s2.comm, "my test proc");
    }

    #[test]
    fn parse_stat_negative_nice() {
        let s = parse_stat(&make_stat("kworker/0:1H", "-5")).unwrap();
        assert_eq!(s.nice, -5);
        assert_eq!(s.blkio_ticks, 42);
    }

    #[test]
    fn rate_computes_speeds() {
        let prev = ProcIo {
            rchar: 1000,
            wchar: 2000,
            syscr: 0,
            syscw: 0,
            read_bytes: 1024,
            write_bytes: 2048,
            cancelled_write_bytes: 0,
        };
        let cur = ProcIo {
            rchar: 3000,
            wchar: 6000,
            syscr: 0,
            syscw: 0,
            read_bytes: 5120,
            write_bytes: 8192,
            cancelled_write_bytes: 0,
        };
        let r = rate(&prev, 100, &cur, 350, 2.0);
        assert!((r.rchar_s - 1000.0).abs() < 1e-9);
        assert!((r.wchar_s - 2000.0).abs() < 1e-9);
        // 2s 内新增磁盘读 4096B = 4KiB → 2 KiB/s
        assert!((r.read_kbps - 2.0).abs() < 1e-9);
        assert!((r.write_kbps - 3.0).abs() < 1e-9);
        // 250 tick × 10ms = 2500ms
        assert_eq!(r.iodelay_ms, 2500);
    }
}
