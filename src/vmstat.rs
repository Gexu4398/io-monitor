//! /proc/vmstat 的 pgpgin / pgpgout。
//!
//! iotop 的 Actual DISK READ/WRITE 用的就是这两个计数，单位是 KiB，
//! 乘 1024 得到字节。它统计的是虚拟内存换入换出的页，不会把整盘、分区、
//! dm 设备重复加总。

use std::fs;

/// 解析 vmstat 文本，返回 (读字节, 写字节)。缺任一字段则失败。
pub fn parse(content: &str) -> Option<(u64, u64)> {
    let mut pgpgin = None;
    let mut pgpgout = None;
    for line in content.lines() {
        let mut parts = line.split_whitespace();
        match (parts.next(), parts.next()) {
            (Some("pgpgin"), Some(v)) => pgpgin = v.parse::<u64>().ok(),
            (Some("pgpgout"), Some(v)) => pgpgout = v.parse::<u64>().ok(),
            _ => {}
        }
    }
    Some((pgpgin? * 1024, pgpgout? * 1024))
}

pub fn read() -> Option<(u64, u64)> {
    let content = fs::read_to_string("/proc/vmstat").ok()?;
    parse(&content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_page_counters_as_bytes() {
        let text = "\
nr_free_pages 12345
pgpgin 1000
pgpgout 2048
pswpin 3
";
        assert_eq!(parse(text), Some((1000 * 1024, 2048 * 1024)));
    }

    #[test]
    fn rejects_incomplete_vmstat() {
        assert_eq!(parse("pgpgin 10\n"), None);
        assert_eq!(parse("pgpgout 10\n"), None);
        assert_eq!(parse("pgpgin nope\npgpgout 1\n"), None);
    }
}
