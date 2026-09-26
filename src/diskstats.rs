//! /proc/diskstats 解析与差值速率计算。
//! 字段定义见内核文档 Documentation/admin-guide/iostats.rst。

use std::fs;
use std::io;

/// 单个块设备自系统启动以来的累计计数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiskStats {
    pub major: u32,
    pub minor: u32,
    pub device: String,
    pub reads_completed: u64,
    pub reads_merged: u64,
    pub sectors_read: u64,
    pub time_reading_ms: u64,
    pub writes_completed: u64,
    pub writes_merged: u64,
    pub sectors_written: u64,
    pub time_writing_ms: u64,
    pub in_flight: u64,
    pub io_time_ms: u64,
    pub weighted_io_time_ms: u64,
}

/// 解析 /proc/diskstats 的完整内容（每行一个设备）。
pub fn parse(content: &str) -> Result<Vec<DiskStats>, String> {
    let mut out = Vec::new();
    for (lineno, line) in content.lines().enumerate() {
        if line.trim().is_empty() {
            continue;
        }
        let stats = parse_line(line).map_err(|e| format!("第 {} 行: {}", lineno + 1, e))?;
        out.push(stats);
    }
    Ok(out)
}

fn parse_line(line: &str) -> Result<DiskStats, String> {
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 14 {
        return Err(format!("字段数不足: {}（至少需要 14 个）", fields.len()));
    }
    let num = |i: usize| -> Result<u64, String> {
        fields[i]
            .parse::<u64>()
            .map_err(|_| format!("第 {} 个字段不是有效数字: \"{}\"", i + 1, fields[i]))
    };
    Ok(DiskStats {
        major: num(0)? as u32,
        minor: num(1)? as u32,
        device: fields[2].to_string(),
        reads_completed: num(3)?,
        reads_merged: num(4)?,
        sectors_read: num(5)?,
        time_reading_ms: num(6)?,
        writes_completed: num(7)?,
        writes_merged: num(8)?,
        sectors_written: num(9)?,
        time_writing_ms: num(10)?,
        in_flight: num(11)?,
        io_time_ms: num(12)?,
        weighted_io_time_ms: num(13)?,
        // 内核 4.18+ 的行尾还有 discard/flush 的附加字段，这里用不到，直接忽略
    })
}

/// 是否为 loop/ram 等虚拟设备（默认视图隐藏这些设备）。
pub fn is_pseudo_device(name: &str) -> bool {
    name.starts_with("loop")
        || name.starts_with("ram")
        || name.starts_with("zram")
        || name.starts_with("sr")
}

/// 读取当前的 /proc/diskstats。
pub fn read() -> io::Result<Vec<DiskStats>> {
    let content = fs::read_to_string("/proc/diskstats")?;
    parse(&content).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

/// 一个采样间隔内的设备 IO 速率。
pub struct DiskRate {
    pub device: String,
    /// 每秒读完成次数
    pub r_s: f64,
    /// 每秒写完成次数
    pub w_s: f64,
    /// 每秒读吞吐 KiB（扇区按内核口径 512B 换算）
    pub rk_bps: f64,
    pub wk_bps: f64,
    /// 平均队列长度
    pub aqu_sz: f64,
    /// 平均每次 IO 耗时（毫秒，读写合计）
    pub await_ms: f64,
    /// 间隔内设备处理 IO 的时间占比
    pub util_pct: f64,
    /// 本间隔内是否有任何 IO 活动计数
    pub active: bool,
}

/// 由前后两个样本计算单设备速率。
/// 计数器理论上只增不减，但设备移除/重置时可能倒退，统一用 saturating_sub 防御。
fn rate(prev: &DiskStats, cur: &DiskStats, elapsed_s: f64) -> DiskRate {
    let d_reads = cur.reads_completed.saturating_sub(prev.reads_completed);
    let d_sect_r = cur.sectors_read.saturating_sub(prev.sectors_read);
    let d_writes = cur.writes_completed.saturating_sub(prev.writes_completed);
    let d_sect_w = cur.sectors_written.saturating_sub(prev.sectors_written);
    let d_read_ms = cur.time_reading_ms.saturating_sub(prev.time_reading_ms);
    let d_write_ms = cur.time_writing_ms.saturating_sub(prev.time_writing_ms);
    let d_io_ms = cur.io_time_ms.saturating_sub(prev.io_time_ms);
    let d_weighted_ms = cur
        .weighted_io_time_ms
        .saturating_sub(prev.weighted_io_time_ms);

    let ios = d_reads + d_writes;
    DiskRate {
        device: cur.device.clone(),
        r_s: d_reads as f64 / elapsed_s,
        w_s: d_writes as f64 / elapsed_s,
        rk_bps: d_sect_r as f64 * 512.0 / 1024.0 / elapsed_s,
        wk_bps: d_sect_w as f64 * 512.0 / 1024.0 / elapsed_s,
        aqu_sz: d_weighted_ms as f64 / 1000.0 / elapsed_s,
        await_ms: if ios > 0 {
            (d_read_ms + d_write_ms) as f64 / ios as f64
        } else {
            0.0
        },
        util_pct: d_io_ms as f64 / (elapsed_s * 1000.0) * 100.0,
        active: d_reads + d_writes + d_sect_r + d_sect_w > 0,
    }
}

/// 按设备号配对前后样本并计算每个设备的速率；只出现在其中一侧的设备被跳过。
pub fn rates(prev: &[DiskStats], cur: &[DiskStats], elapsed_s: f64) -> Vec<DiskRate> {
    cur.iter()
        .filter_map(|c| {
            let p = prev
                .iter()
                .find(|p| p.major == c.major && p.minor == c.minor)?;
            Some(rate(p, c, elapsed_s))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "   7       0 loop7 0 0 0 0 0 0 0 0 0 0 0\n\
       8       0 sda 79522 2676 3235360 78160 2100782 1033836 8701080 16552390 0 2491280 17331450 0 0 0 0 0 0\n\
       8       1 sda1 79187 2673 3228296 77120 2098544 1033682 8666688 16544524 0 2491160 17322160";

    #[test]
    fn parse_diskstats_sample() {
        let disks = parse(SAMPLE).expect("解析应成功");
        assert_eq!(disks.len(), 3);

        let sda = &disks[1];
        assert_eq!((sda.major, sda.minor), (8, 0));
        assert_eq!(sda.device, "sda");
        assert_eq!(sda.reads_completed, 79522);
        assert_eq!(sda.reads_merged, 2676);
        assert_eq!(sda.sectors_read, 3235360);
        assert_eq!(sda.time_reading_ms, 78160);
        assert_eq!(sda.writes_completed, 2100782);
        assert_eq!(sda.io_time_ms, 2491280);
        assert_eq!(sda.weighted_io_time_ms, 17331450);
    }

    #[test]
    fn parse_rejects_short_line() {
        assert!(parse_line("8 0 sda 1 2 3").is_err());
    }

    #[test]
    fn parse_rejects_non_numeric() {
        assert!(parse_line("8 0 sda x 0 0 0 0 0 0 0 0 0 0").is_err());
    }

    #[allow(clippy::too_many_arguments)]
    fn stats(
        reads: u64,
        sect_r: u64,
        read_ms: u64,
        writes: u64,
        sect_w: u64,
        write_ms: u64,
        io_ms: u64,
        weighted_ms: u64,
    ) -> DiskStats {
        DiskStats {
            major: 8,
            minor: 0,
            device: "sda".to_string(),
            reads_completed: reads,
            reads_merged: 0,
            sectors_read: sect_r,
            time_reading_ms: read_ms,
            writes_completed: writes,
            writes_merged: 0,
            sectors_written: sect_w,
            time_writing_ms: write_ms,
            in_flight: 0,
            io_time_ms: io_ms,
            weighted_io_time_ms: weighted_ms,
        }
    }

    #[test]
    fn rate_computes_speeds() {
        let prev = stats(100, 200, 0, 50, 400, 0, 1000, 0);
        let cur = stats(110, 400, 40, 50, 1400, 60, 3000, 4000);
        let r = rate(&prev, &cur, 2.0);

        assert!((r.r_s - 5.0).abs() < 1e-9);
        assert!((r.w_s - 0.0).abs() < 1e-9);
        // 2s 内读了 200 扇区 = 100KiB → 50 KiB/s
        assert!((r.rk_bps - 50.0).abs() < 1e-9);
        assert!((r.wk_bps - 250.0).abs() < 1e-9);
        // 10 次读、0 次写，共耗时 (40+60)ms → 每次 10ms
        assert!((r.await_ms - 10.0).abs() < 1e-9);
        // 2000ms IO 时间 / 2000ms 间隔 = 100%
        assert!((r.util_pct - 100.0).abs() < 1e-9);
        // 4000ms 加权时间 / 2s = 平均队列长度 2
        assert!((r.aqu_sz - 2.0).abs() < 1e-9);
        assert!(r.active);
    }

    #[test]
    fn rate_marks_inactive() {
        let prev = stats(100, 200, 0, 50, 400, 0, 1000, 0);
        let cur = stats(100, 200, 0, 50, 400, 0, 1000, 0);
        let r = rate(&prev, &cur, 2.0);
        assert!(!r.active);
        assert!((r.await_ms - 0.0).abs() < 1e-9);
    }

    #[test]
    fn rates_pairs_by_device_number() {
        let mut sdb_prev = stats(10, 20, 0, 0, 0, 0, 0, 0);
        sdb_prev.device = "sdb".to_string();
        sdb_prev.minor = 16;
        let mut sdb_cur = stats(20, 40, 0, 0, 0, 0, 0, 0);
        sdb_cur.device = "sdb".to_string();
        sdb_cur.minor = 16;

        let sda_prev = stats(0, 0, 0, 0, 0, 0, 0, 0);
        let sda_cur = stats(5, 10, 0, 0, 0, 0, 0, 0);

        let out = rates(&[sdb_prev, sda_prev], &[sdb_cur, sda_cur], 1.0);
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].device, "sdb");
        assert!((out[0].r_s - 10.0).abs() < 1e-9);
        assert_eq!(out[1].device, "sda");
        assert!((out[1].r_s - 5.0).abs() < 1e-9);

        // 只在 cur 中出现（没有 prev 配对）的设备应被跳过
        let extra = stats(1, 1, 0, 0, 0, 0, 0, 0);
        assert_eq!(rates(&[], &[extra], 1.0).len(), 0);
    }
}
