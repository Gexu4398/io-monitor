//! taskstats（NETLINK_GENERIC）查询。
//!
//! iotop 的 SWAPIN% 与 IO% 来自这里的 swapin_delay_total / blkio_delay_total，
//! 单位是纳秒。/proc 里没有换入延迟；stat 第 42 字段只有 blkio，而且是 clock tick。
//! 内核对 TASKSTATS_CMD_GET 要求 CAP_NET_ADMIN，没有该权限时调用方改走 tick 估算。
//!
//! struct taskstats 在版本 15 往前部插入了 delay_max/min，blkio/swapin 的偏移因此不同。
//! 其余版本（含 16 及以后）沿用 v14 布局，与 iotop 的处理一致。

#[cfg(target_os = "linux")]
use crate::syscall;

/// 一个线程自启动以来的延迟累计，单位纳秒。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Delays {
    pub blkio_ns: u64,
    pub swapin_ns: u64,
}

const NLMSG_ERROR: u16 = 2;
#[cfg(target_os = "linux")]
const GENL_ID_CTRL: u16 = 0x10;
#[cfg(target_os = "linux")]
const CTRL_CMD_GETFAMILY: u8 = 3;
#[cfg(target_os = "linux")]
const CTRL_ATTR_FAMILY_ID: u16 = 1;
#[cfg(target_os = "linux")]
const CTRL_ATTR_FAMILY_NAME: u16 = 2;
#[cfg(target_os = "linux")]
const TASKSTATS_CMD_GET: u8 = 1;
#[cfg(target_os = "linux")]
const TASKSTATS_CMD_ATTR_PID: u16 = 1;
const TASKSTATS_TYPE_STATS: u16 = 3;
const TASKSTATS_TYPE_AGGR_PID: u16 = 4;
const TASKSTATS_TYPE_AGGR_TGID: u16 = 5;

pub struct Taskstats {
    disabled: bool,
    #[cfg(target_os = "linux")]
    fd: i32,
    #[cfg(target_os = "linux")]
    family: u16,
    #[cfg(target_os = "linux")]
    buf: Vec<u8>,
    #[cfg(target_os = "linux")]
    seq: u32,
}

impl Taskstats {
    /// 打开 netlink 并解析 TASKSTATS 族 ID。失败时返回 None，调用方应退回 /proc。
    pub fn open() -> Option<Self> {
        #[cfg(target_os = "linux")]
        {
            let fd = syscall::netlink_socket().ok()?;
            if syscall::bind_netlink(fd).is_err() {
                syscall::close(fd);
                return None;
            }
            // 超时设不上也还能用，只是极端情况下一次查询可能多等一会儿。
            let _ = syscall::set_recv_timeout(fd);
            let mut buf = vec![0u8; 2048];
            let family = match family_id(fd, &mut buf) {
                Some(id) if id != 0 => id,
                _ => {
                    syscall::close(fd);
                    return None;
                }
            };
            let mut ts = Self {
                disabled: false,
                fd,
                family,
                buf,
                seq: 0,
            };
            // 先探一次 pid 1。没有 CAP_NET_ADMIN 时会 EPERM，立刻停用，
            // 避免每个线程都空转一圈，也避免同一次采样里混用两种数据源。
            let _ = ts.query(1);
            Some(ts)
        }
        #[cfg(not(target_os = "linux"))]
        {
            None
        }
    }

    /// 查询一个 TID。权限不足时把套接字标为停用并返回 None。
    pub fn query(&mut self, tid: u32) -> Option<Delays> {
        if self.disabled {
            return None;
        }
        #[cfg(target_os = "linux")]
        {
            match self.roundtrip(tid) {
                Ok(d) => Some(d),
                // EPERM / EACCES：这个权限对所有线程都一样，不用再试。
                Err(1) | Err(13) => {
                    self.disabled = true;
                    None
                }
                Err(_) => None,
            }
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = tid;
            None
        }
    }

    #[cfg(target_os = "linux")]
    fn roundtrip(&mut self, tid: u32) -> Result<Delays, i32> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let payload = tid.to_le_bytes();
        let req = encode_request(self.family, TASKSTATS_CMD_GET, TASKSTATS_CMD_ATTR_PID, &payload, seq);
        syscall::send_netlink(self.fd, &req)?;
        let n = syscall::recv_netlink(self.fd, &mut self.buf)?;
        delays_from_reply(&self.buf[..n])
    }
}

#[cfg(target_os = "linux")]
impl Drop for Taskstats {
    fn drop(&mut self) {
        if self.fd >= 0 {
            syscall::close(self.fd);
        }
    }
}

#[cfg(target_os = "linux")]
fn family_id(fd: i32, buf: &mut [u8]) -> Option<u16> {
    let name = b"TASKSTATS\0";
    let req = encode_request(GENL_ID_CTRL, CTRL_CMD_GETFAMILY, CTRL_ATTR_FAMILY_NAME, name, 1);
    syscall::send_netlink(fd, &req).ok()?;
    let n = syscall::recv_netlink(fd, buf).ok()?;
    if nl_errno(&buf[..n]).is_some() {
        return None;
    }
    let attrs = message_payload(&buf[..n])?;
    let mut id = None;
    walk_attrs(attrs, |ty, payload| {
        if ty == CTRL_ATTR_FAMILY_ID && payload.len() >= 2 {
            id = read_u16(payload, 0);
            true
        } else {
            false
        }
    });
    id
}

/// 从一条 taskstats 应答里取出延迟。错误报文返回正的 errno。
pub(crate) fn delays_from_reply(buf: &[u8]) -> Result<Delays, i32> {
    if let Some(err) = nl_errno(buf) {
        return Err(err);
    }
    let attrs = message_payload(buf).ok_or(22)?;
    let stats = find_stats(attrs).ok_or(22)?;
    parse_delays(stats).ok_or(22)
}

pub(crate) fn parse_delays(stats: &[u8]) -> Option<Delays> {
    let version = read_u16(stats, 0)?;
    // v15 在 cpu_delay_total 之后插入了 max/min，后面的字段整体后移 16 字节，
    // blkio 自身又多了 max/min，所以 swapin 再后移 16 字节。
    let (blkio_off, swapin_off) = if version == 15 {
        (56, 88)
    } else if version >= 1 {
        (40, 56)
    } else {
        return None;
    };
    Some(Delays {
        blkio_ns: read_u64(stats, blkio_off)?,
        swapin_ns: read_u64(stats, swapin_off)?,
    })
}

fn find_stats(attrs: &[u8]) -> Option<&[u8]> {
    let mut off = 0;
    while off + 4 <= attrs.len() {
        let nla_len = match read_u16(attrs, off) {
            Some(n) => usize::from(n),
            None => break,
        };
        let ty = match read_u16(attrs, off + 2) {
            Some(t) => t & 0x3fff,
            None => break,
        };
        if nla_len < 4 || off + nla_len > attrs.len() {
            break;
        }
        let payload = &attrs[off + 4..off + nla_len];
        if ty == TASKSTATS_TYPE_STATS {
            return Some(payload);
        }
        if ty == TASKSTATS_TYPE_AGGR_PID || ty == TASKSTATS_TYPE_AGGR_TGID {
            if let Some(stats) = find_stats(payload) {
                return Some(stats);
            }
        }
        let step = (nla_len + 3) & !3;
        if step == 0 {
            break;
        }
        off += step;
    }
    None
}

/// 返回 true 表示停止遍历。
#[cfg(target_os = "linux")]
fn walk_attrs(buf: &[u8], mut f: impl FnMut(u16, &[u8]) -> bool) {
    let mut off = 0;
    while off + 4 <= buf.len() {
        let Some(nla_len) = read_u16(buf, off).map(usize::from) else {
            break;
        };
        let Some(ty) = read_u16(buf, off + 2) else {
            break;
        };
        if nla_len < 4 || off + nla_len > buf.len() {
            break;
        }
        let payload = &buf[off + 4..off + nla_len];
        if f(ty & 0x3fff, payload) {
            return;
        }
        let step = (nla_len + 3) & !3;
        if step == 0 {
            break;
        }
        off += step;
    }
}

fn message_payload(buf: &[u8]) -> Option<&[u8]> {
    if buf.len() < 20 {
        return None;
    }
    let nl_len = u32::from_le_bytes(buf[..4].try_into().ok()?) as usize;
    let end = nl_len.min(buf.len());
    if end < 20 {
        return None;
    }
    Some(&buf[20..end])
}

/// 内核把 errno 的相反数放在 NLMSG_ERROR 的第一个 int 里。
fn nl_errno(buf: &[u8]) -> Option<i32> {
    if buf.len() < 20 {
        return None;
    }
    let ty = read_u16(buf, 4)?;
    if ty != NLMSG_ERROR {
        return None;
    }
    let err = i32::from_le_bytes(buf[16..20].try_into().ok()?);
    if err < 0 {
        Some(-err)
    } else {
        None
    }
}

#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
fn encode_request(nl_type: u16, cmd: u8, attr: u16, data: &[u8], seq: u32) -> Vec<u8> {
    let nla_len = 4 + data.len();
    let aligned = (nla_len + 3) & !3;
    let total = 20 + aligned;
    let mut buf = vec![0u8; total];
    buf[0..4].copy_from_slice(&(total as u32).to_le_bytes());
    buf[4..6].copy_from_slice(&nl_type.to_le_bytes());
    buf[6..8].copy_from_slice(&1u16.to_le_bytes()); // NLM_F_REQUEST
    buf[8..12].copy_from_slice(&seq.to_le_bytes());
    buf[16] = cmd;
    buf[17] = 1;
    buf[20..22].copy_from_slice(&(nla_len as u16).to_le_bytes());
    buf[22..24].copy_from_slice(&attr.to_le_bytes());
    buf[24..24 + data.len()].copy_from_slice(data);
    buf
}

fn read_u16(buf: &[u8], off: usize) -> Option<u16> {
    let bytes = buf.get(off..off + 2)?;
    Some(u16::from_le_bytes(bytes.try_into().ok()?))
}

fn read_u64(buf: &[u8], off: usize) -> Option<u64> {
    let bytes = buf.get(off..off + 8)?;
    Some(u64::from_le_bytes(bytes.try_into().ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn put_u16(buf: &mut [u8], off: usize, v: u16) {
        buf[off..off + 2].copy_from_slice(&v.to_le_bytes());
    }

    fn put_u64(buf: &mut [u8], off: usize, v: u64) {
        buf[off..off + 8].copy_from_slice(&v.to_le_bytes());
    }

    #[test]
    fn v14_offsets() {
        let mut stats = vec![0u8; 64];
        put_u16(&mut stats, 0, 8);
        put_u64(&mut stats, 40, 111);
        put_u64(&mut stats, 56, 222);
        let d = parse_delays(&stats).unwrap();
        assert_eq!(d.blkio_ns, 111);
        assert_eq!(d.swapin_ns, 222);
    }

    #[test]
    fn v15_offsets_skip_inserted_minmax() {
        let mut stats = vec![0u8; 96];
        put_u16(&mut stats, 0, 15);
        // 若误用 v14 偏移，这里会被读成 blkio。
        put_u64(&mut stats, 40, 999);
        put_u64(&mut stats, 56, 111);
        put_u64(&mut stats, 88, 222);
        let d = parse_delays(&stats).unwrap();
        assert_eq!(d.blkio_ns, 111);
        assert_eq!(d.swapin_ns, 222);
    }

    #[test]
    fn rejects_short_or_unknown_version() {
        assert!(parse_delays(&[]).is_none());
        let mut stats = vec![0u8; 64];
        put_u16(&mut stats, 0, 0);
        assert!(parse_delays(&stats).is_none());
        put_u16(&mut stats, 0, 15);
        assert!(parse_delays(&stats).is_none());
    }

    fn nla(ty: u16, payload: &[u8]) -> Vec<u8> {
        let nla_len = 4 + payload.len();
        let aligned = (nla_len + 3) & !3;
        let mut buf = vec![0u8; aligned];
        buf[0..2].copy_from_slice(&(nla_len as u16).to_le_bytes());
        buf[2..4].copy_from_slice(&ty.to_le_bytes());
        buf[4..4 + payload.len()].copy_from_slice(payload);
        buf
    }

    #[test]
    fn parses_nested_aggr_pid() {
        let mut stats = vec![0u8; 64];
        put_u16(&mut stats, 0, 14);
        put_u64(&mut stats, 40, 50);
        put_u64(&mut stats, 56, 60);
        let inner = {
            let mut v = nla(1, &7u32.to_le_bytes());
            v.extend(nla(TASKSTATS_TYPE_STATS, &stats));
            v
        };
        let attrs = nla(TASKSTATS_TYPE_AGGR_PID, &inner);
        let total = 20 + attrs.len();
        let mut msg = vec![0u8; total];
        msg[0..4].copy_from_slice(&(total as u32).to_le_bytes());
        msg[4..6].copy_from_slice(&20u16.to_le_bytes());
        msg[20..].copy_from_slice(&attrs);
        let d = delays_from_reply(&msg).unwrap();
        assert_eq!(d.blkio_ns, 50);
        assert_eq!(d.swapin_ns, 60);
    }

    #[test]
    fn nlmsg_error_becomes_errno() {
        let mut msg = vec![0u8; 20];
        msg[0..4].copy_from_slice(&20u32.to_le_bytes());
        msg[4..6].copy_from_slice(&NLMSG_ERROR.to_le_bytes());
        msg[16..20].copy_from_slice(&(-1i32).to_le_bytes());
        assert_eq!(delays_from_reply(&msg), Err(1));
    }
}
