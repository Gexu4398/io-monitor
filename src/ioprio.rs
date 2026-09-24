//! IO 调度优先级，对应 iotop 的 PRIO 列。
//!
//! 优先用 ioprio_get 的结果。类别为 NONE（进程没调用过 ionice）时，
//! 内核按调度策略和 nice 换算：普通进程 (nice+20)/5，默认就是 be/4；
//! SCHED_FIFO/RR 显示为 rt/N；SCHED_IDLE 显示为 idle。

use crate::syscall;

const CLASS_SHIFT: i32 = 13;
const CLASS_RT: i32 = 1;
const CLASS_BE: i32 = 2;
const CLASS_IDLE: i32 = 3;

/// 读指定线程的 IO 优先级并格式化成 iotop 的 `be/4`、`rt/4`、`idle`。
pub fn read_ioprio(tid: u32, nice: i64, policy: u32) -> String {
    format_ioprio(syscall::ioprio_get(tid), nice, policy)
}

/// `raw` 为 ioprio_get 的返回值；None 或类别 NONE 时用 stat 里的 nice/policy 换算。
pub fn format_ioprio(raw: Option<i32>, nice: i64, policy: u32) -> String {
    let prio = match raw {
        Some(p) if (p >> CLASS_SHIFT) > 0 => p,
        _ => from_sched(nice, policy),
    };
    let class = prio >> CLASS_SHIFT;
    let data = prio & ((1 << CLASS_SHIFT) - 1);
    match class {
        CLASS_RT => format!("rt/{}", data),
        CLASS_BE => format!("be/{}", data),
        CLASS_IDLE => "idle".to_string(),
        _ => "?".to_string(),
    }
}

/// 与内核 task_nice_ioclass / task_nice_ioprio 相同的换算。
fn from_sched(nice: i64, policy: u32) -> i32 {
    // nice 的取值是 -20..=19，加 20 后不会为负。
    let level = ((nice + 20) / 5).clamp(0, 7) as i32;
    // sched.h：1=FIFO，2=RR，5=IDLE，其余（OTHER/BATCH/DEADLINE）按 best-effort。
    let class = match policy {
        1 | 2 => CLASS_RT,
        5 => CLASS_IDLE,
        _ => CLASS_BE,
    };
    (class << CLASS_SHIFT) | level
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_nice_is_be4() {
        // 没设过 ionice 的普通进程：nice 0 → (0+20)/5 = 4。
        assert_eq!(format_ioprio(None, 0, 0), "be/4");
    }

    #[test]
    fn realtime_scheduler_is_rt4() {
        // migration/watchdog 是 SCHED_FIFO，nice 仍是 0，所以是 rt/4 而不是 rt/99。
        assert_eq!(format_ioprio(None, 0, 1), "rt/4");
        assert_eq!(format_ioprio(None, 0, 2), "rt/4");
    }

    #[test]
    fn high_nice_kworker_is_be0() {
        // kworker/N:MH 的 nice 为 -20：(0)/5 = 0。
        assert_eq!(format_ioprio(None, -20, 0), "be/0");
    }

    #[test]
    fn explicit_ioprio_wins_over_nice() {
        // ionice -c2 -n0：类别 BE=2，级别 0，即使 nice 是 0 也显示 be/0。
        assert_eq!(format_ioprio(Some((2 << 13) | 0), 0, 0), "be/0");
        assert_eq!(format_ioprio(Some(3 << 13), 0, 0), "idle");
        assert_eq!(format_ioprio(Some((1 << 13) | 4), 0, 0), "rt/4");
    }

    #[test]
    fn class_none_falls_back_to_scheduler() {
        assert_eq!(format_ioprio(Some(0), 0, 0), "be/4");
        assert_eq!(format_ioprio(Some(0), 0, 5), "idle");
    }
}
