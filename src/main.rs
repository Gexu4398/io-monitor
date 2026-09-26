//! iomon —— Linux IO 监控工具
//!
//! 直接读取 /proc/diskstats 与 /proc/<pid>/io，按采样间隔计算差值，
//! 输出 iostat 风格的磁盘/进程 IO 速率。零第三方依赖。

mod records;
mod diskstats;
mod ioprio;
mod iotop;
mod json;
mod proc_io;
mod syscall;
mod taskstats;
mod vmstat;
mod web;

use std::process::exit;
use std::thread::sleep;
use std::time::{Duration, Instant};

use diskstats::{DiskRate, DiskStats};
use iotop::TopOptions;
use proc_io::ProcIo;

const USAGE: &str = "\
iomon —— Linux IO 监控工具（零依赖，直接读取 /proc）

用法:
    iomon [选项] [间隔秒数] [次数]          设备级速率视图
    iomon top [选项] [间隔秒数] [次数]      进程/线程 IO 排行（iotop 风格）
    iomon web [间隔秒数]                    浏览器查看页，默认 http://127.0.0.1:8080

位置参数:
    间隔秒数    采样间隔，支持小数，默认 2
    次数        采样次数，省略则一直运行

选项（设备视图）:
    -p, --pid <PID>      同时监控指定进程的 IO 与 iodelay
    -d, --device <NAME>  只显示指定设备，可多次给出（如 -d sda -d nvme0n1）
    -a, --all            显示全部设备（默认隐藏 loop/ram 等虚拟设备及无活动设备）
    -h, --help           显示本帮助

选项（top 视图，用 iomon top --help 查看）:
    -P                   按进程聚合显示（默认按线程）
    -o                   只显示有 IO 活动的条目（默认全部，与 iotop 相同）
    -n, --lines <N>      最多显示 N 行（默认：终端一屏，否则 20）
    -a, --all            显示无 IO 活动的条目（默认已开启）

示例:
    iomon                      # 每 2 秒刷新一次磁盘 IO 速率
    iomon 5 12                 # 每 5 秒一次，共输出 12 次
    iomon 1 -d sda -d dm-0     # 只看 sda 与 dm-0
    iomon -p $(pidof java) 1   # 同时观察某进程的读写速率与 IO 等待
    iomon top -P 1             # iotop 风格：每 1 秒刷新进程 IO 排行
    iomon web                  # 浏览器打开 http://127.0.0.1:8080
    iomon web 2 -l 9090        # 每 2 秒采样，只监听 9090 端口
";

const USAGE_TOP: &str = "\
iomon top —— 进程/线程 IO 排行（iotop 风格）

用法:
    iomon top [选项] [间隔秒数] [次数]

位置参数:
    间隔秒数    采样间隔，支持小数，默认 2
    次数        采样次数，省略则一直运行

选项:
    -P, --processes     按进程聚合显示（默认按线程）
    -o, --only          只显示有 IO 活动的条目（默认显示全部）
    -n, --lines <N>     最多显示 N 行（默认：终端一屏，否则 20）
    -a, --all           显示无 IO 活动的条目（默认已开启）
    -h, --help          显示本帮助

说明:
    Total 为全部线程差值求和（进程视角，写字节已扣除 cancelled）。
    Actual 为 /proc/vmstat 的 pgpgin/pgpgout 差值，与 iotop 相同。
    PRIO 为 IO 优先级（ioprio_get；未设置时按 nice 换算，普通进程是 be/4）。
    IO> / SWAPIN 来自 taskstats 的延迟占比，需要 root 或 CAP_NET_ADMIN；
    没有该权限时 IO> 改用 /proc stat 的 blkio tick，SWAPIN 为 0。
    读取其他用户的线程需要 root 权限。kernel.task_delayacct=0 时
    IO> 与 SWAPIN 恒为 0。

示例:
    iomon top                 # 每 2 秒刷新全部线程的 IO 排行
    iomon top -P 1            # 每 1 秒，按进程聚合
    iomon top -a -n 40 5 12   # 显示 40 行（含零活动），5 秒一次共 12 次
";

struct Args {
    interval: f64,
    count: Option<u64>,
    pid: Option<u32>,
    devices: Vec<String>,
    all: bool,
}

/// 一次采样的全部原始数据。
struct Snapshot {
    at: Instant,
    disks: Vec<DiskStats>,
    proc_io: Option<ProcIo>,
    /// delayacct_blkio_ticks，单位是 USER_HZ（通常 1 tick = 10ms），不是毫秒。
    blkio_ticks: Option<u64>,
}

fn main() {
    let argv: Vec<String> = std::env::args().collect();
    if argv.get(1).map(String::as_str) == Some("web") {
        let opts = match web::parse_args(&argv[2..]) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("错误: {}\n\n{}", e, web::USAGE);
                exit(2);
            }
        };
        web::serve(opts);
        return;
    }

    if !cfg!(target_os = "linux") {
        eprintln!("错误: iomon 依赖 /proc 文件系统，仅支持在 Linux 上运行。");
        exit(1);
    }

    if argv.get(1).map(String::as_str) == Some("top") {
        let opts = match parse_top_args(&argv[2..]) {
            Ok(o) => o,
            Err(e) => {
                eprintln!("错误: {}\n\n{}", e, USAGE_TOP);
                exit(2);
            }
        };
        iotop::run(opts);
        return;
    }

    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("错误: {}\n\n{}", e, USAGE);
            exit(2);
        }
    };

    let mut prev = match snapshot(args.pid) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("错误: {}", e);
            exit(1);
        }
    };

    println!("iomon —— 采样间隔 {}s，Ctrl+C 退出", args.interval);
    print_totals(&prev, &args);

    let mut printed: u64 = 0;
    loop {
        if let Some(c) = args.count {
            if printed >= c {
                break;
            }
        }
        sleep(Duration::from_secs_f64(args.interval));

        let cur = match snapshot(args.pid) {
            Ok(s) => s,
            Err(e) => {
                eprintln!("\n错误: {}", e);
                exit(1);
            }
        };
        // 用真实经过时间做分母，比固定间隔更稳（不受采样本身耗时影响）
        let elapsed = cur.at.duration_since(prev.at).as_secs_f64();
        print_rates(&prev, &cur, elapsed, &args);
        prev = cur;
        printed += 1;
    }
}

fn snapshot(pid: Option<u32>) -> Result<Snapshot, String> {
    let disks = diskstats::read().map_err(|e| format!("读取 /proc/diskstats 失败: {}", e))?;
    let (proc_io, blkio_ticks) = match pid {
        Some(p) => {
            let io = proc_io::read_proc_io(p)
                .map_err(|e| format!("读取 /proc/{}/io 失败: {}（进程是否已退出？）", p, e))?;
            let ticks = proc_io::read_stat(p)
                .map_err(|e| format!("读取 /proc/{}/stat 失败: {}", p, e))?
                .blkio_ticks;
            (Some(io), Some(ticks))
        }
        None => (None, None),
    };
    Ok(Snapshot {
        at: Instant::now(),
        disks,
        proc_io,
        blkio_ticks,
    })
}

fn visible_disks<'a>(disks: &'a [DiskStats], args: &Args) -> Vec<&'a DiskStats> {
    disks
        .iter()
        .filter(|d| {
            if !args.devices.is_empty() {
                return args.devices.iter().any(|n| n == &d.device);
            }
            args.all || !diskstats::is_pseudo_device(&d.device)
        })
        .collect()
}

fn print_totals(s: &Snapshot, args: &Args) {
    let disks = visible_disks(&s.disks, args);
    println!("\n===== 自启动累计 =====");
    if disks.is_empty() {
        println!("（没有匹配的设备）");
    } else {
        let width = disks
            .iter()
            .map(|d| d.device.len())
            .max()
            .unwrap_or(6)
            .max(6);
        println!(
            "{:<w$} {:>12} {:>12} {:>12} {:>12}",
            "Device", "reads", "read_MiB", "writes", "write_MiB",
            w = width
        );
        for d in disks {
            println!(
                "{:<w$} {:>12} {:>12.1} {:>12} {:>12.1}",
                d.device,
                d.reads_completed,
                d.sectors_read as f64 * 512.0 / 1048576.0,
                d.writes_completed,
                d.sectors_written as f64 * 512.0 / 1048576.0,
                w = width
            );
        }
    }
    if let Some(io) = &s.proc_io {
        let pid = args.pid.unwrap();
        // tick 是 USER_HZ，1 tick = 10ms，所以秒数 = tick / 100。
        let delay_s = s.blkio_ticks.unwrap_or(0) as f64 / 100.0;
        println!(
            "\n进程 {} 累计: 磁盘读 {:.1} MiB  磁盘写 {:.1} MiB  iodelay {:.1} s",
            pid,
            io.read_bytes as f64 / 1048576.0,
            io.write_bytes as f64 / 1048576.0,
            delay_s
        );
    }
}

fn print_rates(prev: &Snapshot, cur: &Snapshot, elapsed: f64, args: &Args) {
    let all = diskstats::rates(&prev.disks, &cur.disks, elapsed);
    let shown: Vec<&DiskRate> = all
        .iter()
        .filter(|r| {
            if !args.devices.is_empty() && !args.devices.iter().any(|n| n == &r.device) {
                return false;
            }
            args.all || (!diskstats::is_pseudo_device(&r.device) && r.active)
        })
        .collect();

    println!("\n===== 最近 {:.1}s =====", elapsed);
    if shown.is_empty() {
        println!("（本间隔内无匹配的设备活动）");
    } else {
        let width = shown
            .iter()
            .map(|r| r.device.len())
            .max()
            .unwrap_or(6)
            .max(6);
        println!(
            "{:<w$} {:>8} {:>8} {:>10} {:>10} {:>7} {:>8} {:>7}",
            "Device", "r/s", "w/s", "rkB/s", "wkB/s", "aqu-sz", "await", "%util",
            w = width
        );
        for r in shown {
            println!(
                "{:<w$} {:>8.1} {:>8.1} {:>10.1} {:>10.1} {:>7.2} {:>8.2} {:>7.1}",
                r.device, r.r_s, r.w_s, r.rk_bps, r.wk_bps, r.aqu_sz, r.await_ms, r.util_pct,
                w = width
            );
        }
    }

    if let (Some(p), Some(c)) = (&prev.proc_io, &cur.proc_io) {
        let pid = args.pid.unwrap();
        let rate = proc_io::rate(
            p,
            prev.blkio_ticks.unwrap_or(0),
            c,
            cur.blkio_ticks.unwrap_or(0),
            elapsed,
        );
        println!(
            "进程 {}: rchar/s {:>13.0}  wchar/s {:>13.0}  磁盘读 {:>9.1} kB/s  磁盘写 {:>9.1} kB/s  iodelay +{} ms",
            pid,
            rate.rchar_s,
            rate.wchar_s,
            rate.read_kbps,
            rate.write_kbps,
            rate.iodelay_ms
        );
    }
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args {
        interval: 2.0,
        count: None,
        pid: None,
        devices: Vec::new(),
        all: false,
    };
    let mut positional: Vec<String> = Vec::new();

    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{}", USAGE);
                exit(0);
            }
            "-a" | "--all" => args.all = true,
            "-p" | "--pid" => {
                let v = it
                    .next()
                    .ok_or_else(|| "-p/--pid 需要一个 PID 参数".to_string())?;
                args.pid = Some(v.parse::<u32>().map_err(|_| format!("无效的 PID: {}", v))?);
            }
            "-d" | "--device" => {
                let v = it
                    .next()
                    .ok_or_else(|| "-d/--device 需要一个设备名参数".to_string())?;
                args.devices.push(v);
            }
            s if s.starts_with('-') => return Err(format!("未知选项: {}", s)),
            s => positional.push(s.to_string()),
        }
    }

    match positional.len() {
        0 => {}
        1 => args.interval = parse_interval(&positional[0])?,
        2 => {
            args.interval = parse_interval(&positional[0])?;
            args.count = Some(
                positional[1]
                    .parse::<u64>()
                    .map_err(|_| format!("无效的次数: {}", positional[1]))?,
            );
        }
        n => return Err(format!("位置参数过多（{} 个），最多为: [间隔秒数] [次数]", n)),
    }
    Ok(args)
}

fn parse_top_args(args: &[String]) -> Result<TopOptions, String> {
    let mut opts = TopOptions {
        interval: 2.0,
        count: None,
        per_process: false,
        show_idle: true,
        rows: 20,
        rows_explicit: false,
    };
    let mut positional: Vec<String> = Vec::new();

    let mut it = args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "-h" | "--help" => {
                print!("{}", USAGE_TOP);
                exit(0);
            }
            "-P" | "--processes" => opts.per_process = true,
            "-o" | "--only" => opts.show_idle = false,
            "-a" | "--all" => opts.show_idle = true,
            "-n" | "--lines" => {
                let v = it
                    .next()
                    .ok_or_else(|| "-n/--lines 需要一个行数参数".to_string())?;
                opts.rows = v
                    .parse::<usize>()
                    .map_err(|_| format!("无效的行数: {}", v))?;
                opts.rows_explicit = true;
                if opts.rows == 0 {
                    return Err("行数必须大于 0".to_string());
                }
            }
            s if s.starts_with('-') => return Err(format!("未知选项: {}", s)),
            s => positional.push(s.to_string()),
        }
    }

    match positional.len() {
        0 => {}
        1 => opts.interval = parse_interval(&positional[0])?,
        2 => {
            opts.interval = parse_interval(&positional[0])?;
            opts.count = Some(
                positional[1]
                    .parse::<u64>()
                    .map_err(|_| format!("无效的次数: {}", positional[1]))?,
            );
        }
        n => return Err(format!("位置参数过多（{} 个），最多为: [间隔秒数] [次数]", n)),
    }
    Ok(opts)
}

fn parse_interval(s: &str) -> Result<f64, String> {
    let v: f64 = s.parse().map_err(|_| format!("无效的间隔秒数: {}", s))?;
    if !v.is_finite() || v <= 0.0 {
        return Err(format!("间隔秒数必须为正数: {}", s));
    }
    Ok(v)
}
