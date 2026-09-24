//! Linux 系统调用封装。只覆盖 ioprio_get、netlink 套接字和终端尺寸，
//! 这样静态二进制不必再依赖 libc crate。

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
mod nr {
    pub const CLOSE: usize = 3;
    pub const IOCTL: usize = 16;
    pub const SOCKET: usize = 41;
    pub const SENDTO: usize = 44;
    pub const RECVFROM: usize = 45;
    pub const BIND: usize = 49;
    pub const SETSOCKOPT: usize = 54;
    pub const IOPRIO_GET: usize = 252;
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
mod nr {
    pub const CLOSE: usize = 57;
    pub const IOCTL: usize = 29;
    pub const SOCKET: usize = 198;
    pub const BIND: usize = 200;
    pub const SENDTO: usize = 206;
    pub const RECVFROM: usize = 207;
    pub const SETSOCKOPT: usize = 208;
    pub const IOPRIO_GET: usize = 31;
}

/// 失败时返回负的 errno。
#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
pub fn syscall6(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "syscall",
            inout("rax") nr => ret,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            out("rcx") _,
            out("r11") _,
            options(nostack),
        );
    }
    ret as isize
}

#[cfg(all(target_os = "linux", target_arch = "aarch64"))]
pub fn syscall6(nr: usize, a0: usize, a1: usize, a2: usize, a3: usize, a4: usize, a5: usize) -> isize {
    let ret: usize;
    unsafe {
        core::arch::asm!(
            "svc #0",
            in("x8") nr,
            inout("x0") a0 => ret,
            in("x1") a1,
            in("x2") a2,
            in("x3") a3,
            in("x4") a4,
            in("x5") a5,
            options(nostack),
        );
    }
    ret as isize
}

#[cfg(all(target_os = "linux", not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn syscall6(_: usize, _: usize, _: usize, _: usize, _: usize, _: usize, _: usize) -> isize {
    -38 // ENOSYS
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
pub fn close(fd: i32) {
    let _ = syscall6(nr::CLOSE, fd as usize, 0, 0, 0, 0, 0);
}

#[cfg(all(target_os = "linux", not(any(target_arch = "x86_64", target_arch = "aarch64"))))]
pub fn close(_fd: i32) {}

#[cfg(target_os = "linux")]
pub fn ioprio_get(tid: u32) -> Option<i32> {
    // 本架构没有 ioprio_get 的调用号时，nr 模块不存在，直接放弃。
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        // IOPRIO_WHO_PROCESS = 1；who 对线程来说就是 TID。
        let ret = syscall6(nr::IOPRIO_GET, 1, tid as usize, 0, 0, 0, 0);
        if ret < 0 {
            None
        } else {
            Some(ret as i32)
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = tid;
        None
    }
}

#[cfg(not(target_os = "linux"))]
pub fn ioprio_get(_tid: u32) -> Option<i32> {
    None
}

/// 终端行数与列数。非终端或 ioctl 失败时返回 None。
pub fn tty_size() -> Option<(usize, usize)> {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        #[repr(C)]
        struct Winsize {
            row: u16,
            col: u16,
            xpixel: u16,
            ypixel: u16,
        }
        let mut ws = Winsize {
            row: 0,
            col: 0,
            xpixel: 0,
            ypixel: 0,
        };
        // TIOCGWINSZ = 0x5413，作用在 stdout。
        let ret = syscall6(nr::IOCTL, 1, 0x5413, &mut ws as *mut Winsize as usize, 0, 0, 0);
        if ret == 0 && ws.row > 0 && ws.col > 0 {
            Some((ws.row as usize, ws.col as usize))
        } else {
            None
        }
    }
    #[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
pub fn netlink_socket() -> Result<i32, i32> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const AF_NETLINK: usize = 16;
        const SOCK_RAW: usize = 3;
        const NETLINK_GENERIC: usize = 16;
        let fd = syscall6(nr::SOCKET, AF_NETLINK, SOCK_RAW, NETLINK_GENERIC, 0, 0, 0);
        if fd < 0 {
            Err((-fd) as i32)
        } else {
            Ok(fd as i32)
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        Err(38)
    }
}

#[cfg(target_os = "linux")]
pub fn bind_netlink(fd: i32) -> Result<(), i32> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        // struct sockaddr_nl：family、pad、pid、groups，共 12 字节。pid=0 由内核分配端口。
        let mut bytes = [0u8; 12];
        bytes[0..2].copy_from_slice(&16u16.to_le_bytes());
        let ret = syscall6(nr::BIND, fd as usize, bytes.as_ptr() as usize, 12, 0, 0, 0);
        if ret < 0 {
            Err((-ret) as i32)
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = fd;
        Err(38)
    }
}

#[cfg(target_os = "linux")]
pub fn set_recv_timeout(fd: i32) -> Result<(), i32> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        const SOL_SOCKET: usize = 1;
        const SO_RCVTIMEO: usize = 20;
        // struct timeval { time_t sec; suseconds_t usec; }，64 位上各 8 字节。
        // 本地 netlink 应答是微秒级的，1 秒只用来避免某次查询卡死整屏刷新。
        let mut tv = [0u8; 16];
        tv[..8].copy_from_slice(&1u64.to_le_bytes());
        let ret = syscall6(
            nr::SETSOCKOPT,
            fd as usize,
            SOL_SOCKET,
            SO_RCVTIMEO,
            tv.as_ptr() as usize,
            16,
            0,
        );
        if ret < 0 {
            Err((-ret) as i32)
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = fd;
        Err(38)
    }
}

#[cfg(target_os = "linux")]
pub fn send_netlink(fd: i32, buf: &[u8]) -> Result<(), i32> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let addr = {
            let mut bytes = [0u8; 12];
            bytes[0..2].copy_from_slice(&16u16.to_le_bytes());
            bytes
        };
        let ret = syscall6(
            nr::SENDTO,
            fd as usize,
            buf.as_ptr() as usize,
            buf.len(),
            0,
            addr.as_ptr() as usize,
            12,
        );
        if ret < 0 {
            Err((-ret) as i32)
        } else {
            Ok(())
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (fd, buf);
        Err(38)
    }
}

#[cfg(target_os = "linux")]
pub fn recv_netlink(fd: i32, buf: &mut [u8]) -> Result<usize, i32> {
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let ret = syscall6(nr::RECVFROM, fd as usize, buf.as_mut_ptr() as usize, buf.len(), 0, 0, 0);
        if ret < 0 {
            Err((-ret) as i32)
        } else {
            Ok(ret as usize)
        }
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        let _ = (fd, buf);
        Err(38)
    }
}
