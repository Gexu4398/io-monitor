# iomon — Linux IO 监控工具

零依赖 Rust 编写的 Linux IO 监控小工具：直接读取 `/proc/diskstats` 与 `/proc/<pid>/io`，按采样间隔计算差值，提供 **iostat 风格的设备速率视图**与 **iotop 风格的进程/线程 IO 排行视图**（`iomon top`）。

## 功能

### 设备级（`iomon`，数据源 `/proc/diskstats`）

| 列 | 含义 |
|----|------|
| r/s、w/s | 每秒读/写完成次数（IOPS） |
| rkB/s、wkB/s | 每秒读/写吞吐（扇区按内核口径 512B 换算） |
| aqu-sz | 平均队列长度 |
| await | 平均每次 IO 耗时（毫秒，读写合计） |
| %util | 间隔内设备处理 IO 的时间占比 |

**进程级**（`-p PID`，数据源 `/proc/<pid>/io` 与 `/proc/<pid>/stat`）：

- `rchar/s`、`wchar/s`：应用视角的读/写速率（包含 page cache 命中）
- 磁盘读/写 kB/s：真正下发到存储层的速率
- iodelay：本间隔内进程阻塞在磁盘 IO 上的时间增量（毫秒）

### iotop 风格排行（`iomon top`）

自动扫描全部进程/线程，按磁盘读写速率排序实时刷新，列和 iotop 对齐：

```
Total DISK READ :     12.34 K/s | Total DISK WRITE:      1.20 M/s
Actual DISK READ:      8.00 K/s | Actual DISK WRITE:    512.00 K/s
    TID PRIO USER      DISK READ   DISK WRITE   SWAPIN      IO>  COMMAND
   5425 be/4 10000       0.00 B/s   147.27 K/s    0.00 %   11.50 %  python3 /opt/hermes/.venv/bin/hermes gateway run
    480 be/4 root        0.00 B/s     3.35 K/s    0.00 %    0.00 %  containerd-shim-runc-v2 -namespace moby
      7 rt/4 root        0.00 B/s     0.00 B/s    0.00 %    0.00 %  [migration/0]
```

- **Total** = 全部线程差值求和（进程记账视角，写字节已减去 `cancelled_write_bytes`）。**Actual** = `/proc/vmstat` 的 `pgpgin`/`pgpgout` 差值，和 iotop 一样，不会把整盘和分区重复加总。
- **PRIO** = IO 优先级（`ioprio_get`）。进程没调用过 `ionice` 时按调度策略和 nice 换算：普通进程是 `be/4`，`SCHED_FIFO`/`RR`（migration、watchdog）是 `rt/4`，高优先级内核线程（nice -20）是 `be/0`。
- **IO>** / **SWAPIN** = 本间隔阻塞在磁盘 IO / 换入上的时间占比，数据来自 taskstats（纳秒），封顶 100%。需要 root 或 `CAP_NET_ADMIN`。没有该权限时 IO> 改用 `/proc/<tid>/stat` 的 blkio tick，SWAPIN 显示 `0.00 %`。
- `kernel.task_delayacct=0`（Linux 5.15+ 的默认）时这两列恒为 0。Ubuntu 宿主机上的开启命令见下文「开启 IO% / SWAPIN（Ubuntu）」。
- 默认按线程显示全部条目（与 iotop 相同）。`-o` 只留有 IO 活动的，`-P` 按进程聚合，`-n N` 限制行数（终端下默认铺满一屏）。
- 线程级计数读自 `/proc/<pid>/task/<tid>/io`（顶层 `/proc/<tid>/io` 是线程组聚合值，不能用来做线程级监控）。
- 读取其他用户的线程需要 root；TTY 下整屏刷新，重定向到文件时自动改为顺序输出。

## 开启 IO% / SWAPIN（Ubuntu）

Linux 5.15 起 `kernel.task_delayacct` 默认关闭。没打开时，页面和 `iomon top` 的 IO、SWAPIN 会一直是 0。在 **Ubuntu 宿主机**上执行（不要在容器里执行；`sudo echo ... > 文件` 无效，重定向发生在 sudo 之前）：

立刻生效：

```bash
echo 1 | sudo tee /proc/sys/kernel/task_delayacct
```

重启后仍然生效：

```bash
echo 'kernel.task_delayacct=1' | sudo tee /etc/sysctl.d/99-task-delayacct.conf
sudo sysctl --system
```

网页上的提示是启动时读的，改完后重启容器才会消失：

```bash
docker compose restart
```

只有进程真的卡在磁盘上时，这两列才会大于 0。机器空闲时继续显示 0 是正常的。

## 构建与运行

> 本工具依赖 `/proc` 文件系统，只能在 **Linux** 上运行。
> 在 Windows 上可以正常编译、运行单元测试，但主程序启动时会提示平台不符。

在 Linux 机器或 WSL 中：

```bash
cargo build --release
./target/release/iomon
```

## 用法

```
iomon [选项] [间隔秒数] [次数]          设备级速率视图
iomon top [选项] [间隔秒数] [次数]      进程/线程 IO 排行（iotop 风格）

-p, --pid <PID>       同时监控指定进程的 IO 与 iodelay（设备视图）
-d, --device <NAME>   只显示指定设备，可多次给出（如 -d sda -d nvme0n1）
-a, --all             显示全部条目（设备视图：含虚拟设备与无活动设备；
                      top 视图：含无 IO 活动的线程/进程，默认已开启）
-P, --processes       top 视图按进程聚合显示（默认按线程）
-o, --only            top 视图只显示有 IO 活动的条目（默认显示全部）
-n, --lines <N>       top 视图最多显示 N 行（默认：终端一屏，否则 20）
-h, --help            显示帮助
```

示例：

```bash
iomon                      # 每 2 秒刷新一次磁盘 IO 速率
iomon 5 12                 # 每 5 秒一次，共输出 12 次
iomon 1 -d sda -d dm-0     # 只看 sda 与 dm-0
iomon -p $(pidof java) 1   # 同时观察某进程的读写速率与 IO 等待
iomon top                  # iotop 风格：每 2 秒刷新全部线程的 IO 排行
iomon top -o 1             # 每 1 秒，只看有 IO 的线程
iomon top -P 1             # 每 1 秒，按进程聚合
iomon top -n 40 5 12       # 最多 40 行，5 秒一次共 12 次
iomon web                  # 浏览器打开 http://127.0.0.1:8080
iomon web 2 -l 9090        # 每 2 秒采样，监听本机 9090
iomon web -l 0.0.0.0:8080  # 显式绑全部网卡，供局域网访问
```

`iomon web` 提供实时视图和记录页 `/records`。默认只监听 `127.0.0.1`（`-l` 只写端口时同样只绑本机）；要对外访问需写全地址（如 `-l 0.0.0.0:8080`）。记录按进程记：某一秒 IO 占比达到阈值（默认 20%）就会留下一条，不必持续。历史写在 `deploy/records`，保留 7 天，更早的自动删掉。页面上可以改阈值、按天查看。Docker Compose 已配好 `-l 0.0.0.0:8080`，映射宿主机 8080 端口。页面会显示全部进程的命令行，对局域网开放前请自行加防火墙或反向代理认证。

输出示例：

```
iomon —— 采样间隔 2s，Ctrl+C 退出

===== 自启动累计 =====
Device        reads    read_MiB       writes   write_MiB
sda           79522        1560.0      2100782      4107.9

===== 最近 2.0s =====
Device          r/s      w/s      rkB/s      wkB/s   aqu-sz    await   %util
sda            12.3     45.6        512.0     2048.0     0.05     1.23     3.4
进程 1234: rchar/s      1048576  wchar/s       524288  磁盘读       0.0 kB/s  磁盘写    1024.0 kB/s  iodelay +15 ms
```

## 说明

- 启动后先输出一屏"自启动累计"总量，之后每个间隔输出差值速率；默认隐藏无活动的设备和 `loop`/`ram` 等虚拟设备，`-a` 可显示全部。
- 计数器倒退（设备移除/重置）会用饱和减法防御，不会产生负值。
- 读取其他用户进程的 `/proc/<pid>/io` 需要同 UID 或 root 权限。`iomon top` 的 SWAPIN / IO% 还需要 `CAP_NET_ADMIN`（taskstats）。
- `%util` 在多队列设备（NVMe）上仅供参考；扇区按内核口径固定 512 字节换算。
- 速率分母使用 `Instant` 实测的间隔耗时，不受采样本身耗时影响。

## Docker 运行（可选）

项目自带 `Dockerfile`（musl 静态二进制 + scratch，镜像约 1.3MB）与 `docker-compose.yaml`
（已配好 `pid: host`、`SYS_PTRACE`、`NET_ADMIN`，并挂载宿主机 `/etc/passwd` 供 top 视图解析用户名）。
`NET_ADMIN` 用来查询 taskstats（SWAPIN / IO%）。compose 按 Ubuntu 默认写了
`apparmor:unconfined`，否则 AppArmor 会拒绝读取宿主机其他进程：

```bash
docker compose build
docker compose up -d                   # 浏览器打开 http://宿主机:8080
docker compose run --rm iomon top 1     # 仍可临时跑命令行排行
docker compose run --rm iomon -p $(pidof java)
docker compose logs -f
```

在容器内监控的同样是宿主机的 IO（`/proc` 为宿主机内核的全局数据）；监控其他用户进程的参数已配好。

## 交叉编译提示（可选）

在 Windows 上为 Linux 构建，最省事的方式是 WSL 内直接 `cargo build --release`；
若要产出 musl 静态二进制：`rustup target add x86_64-unknown-linux-musl` 后
`cargo build --release --target x86_64-unknown-linux-musl`（需要对应 linker，如 `musl-gcc`）。
