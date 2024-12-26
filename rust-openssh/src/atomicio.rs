use std::io::{self, Read, Write};
use std::vec::Vec;
use std::ptr::read;
use std::time::Duration;
///use std::fmt::write;
use std::fmt::{self, Write as FmtWrite};
use std::os::unix::io::RawFd;
use crate::atomicio::ptr::write;
use std::os::fd::FromRawFd;

/// Type alias for read/write function types.
pub type AtomicioRead = fn(RawFd, &mut [u8]) -> io::Result<usize>;
pub type AtomicioWrite = fn(RawFd, &[u8]) -> io::Result<usize>;

/// Ensure all of data on socket comes through. f == read || vwrite.
/// It reads/writes until all data is processed or an error occurs.
use libc::{poll, pollfd, POLLIN, POLLOUT};
///use std::os::unix::io::{RawFd, AsRawFd};
use std::ptr;

// 包装的安全 read 和 write 函数
pub fn safe_read(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    let res = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if res == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as usize)
    }
}

pub fn safe_write(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    let res = unsafe { libc::write(fd, buf.as_ptr() as *const libc::c_void, buf.len()) };
    if res == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(res as usize)
    }
}

// 定义一个简单的函数来模拟 poll 的行为
fn poll_once(fd: RawFd, events: i16) -> io::Result<i32> {
    let mut pfd = pollfd {
        fd,
        events,
        revents: 0,
    };

    // 调用 poll 系统调用
    let ret = unsafe { poll(&mut pfd as *mut pollfd, 1, -1) };

    if ret == -1 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Simplified version of `atomicio6` that does not use callbacks.
pub fn atomicio_no_cb(
    f: fn(RawFd, &mut [u8]) -> io::Result<usize>,
    fd: RawFd,
    buf: &mut [u8],
    n: usize,
) -> io::Result<usize> {
    atomicio6(f, fd, buf, n, None, None)
}

/// Ensure all of data on socket comes through. `f` == `read` || `vwrite`.
/// It reads/writes until all data is processed or an error occurs.
pub fn atomicio(
    f: fn(RawFd, &mut [u8]) -> io::Result<usize>,
    fd: RawFd,
    buf: &mut [u8],
    n: usize,
) -> io::Result<usize> {
    let mut pos = 0;

    while pos < n {
        match f(fd, &mut buf[pos..]) {
            Ok(res) => pos += res,
            Err(e) => return Err(e),
        }
    }

    Ok(pos)
}

pub fn atomicio6(
    f: fn(RawFd, &mut [u8]) -> io::Result<usize>,
    fd: RawFd,
    buf: &mut [u8],
    n: usize,
    cb: Option<fn(&mut u8, usize) -> i32>,
    mut cb_arg: Option<&mut u8>,  // 这里添加了 `mut` 关键字
) -> io::Result<usize> {
    let mut pos = 0;

    while pos < n {
        // 使用 poll 来等待数据就绪
        let poll_result = poll_once(fd, POLLIN);
        match poll_result {
            Ok(_) => {
                let res = f(fd, &mut buf[pos..])?;
                pos += res;

                // 使用 ref mut 来借用 cb_arg，而不是移动它
                if let Some(callback) = cb {
                    if let Some(ref mut arg) = cb_arg {
                        // 使用可变引用
                        if callback(arg, res) == -1 {
                            return Ok(pos); // 如果回调返回-1，退出
                        }
                    }
                }
            }
            Err(e) => return Err(e),
        }
    }

    Ok(pos)
}




/// Ensure all of data on socket comes through. f == readv || writev.
/// This handles multiple buffers (iovec).
pub fn atomiciov6(
    f: fn(RawFd, &mut [u8]) -> io::Result<usize>,
    fd: RawFd,
    iov: &mut [Vec<u8>],
    iovcnt: usize,
    cb: Option<fn(&mut u8, usize) -> i32>,
    mut cb_arg: Option<&mut u8>,  // 这里添加了 `mut` 关键字
) -> Result<usize, io::Error> {
    let mut pos = 0;
    
    // 确保 iovcnt 不大于 iov 的长度
    let iov_len = iov.len();
    if iovcnt > iov_len {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "iovcnt exceeds the length of iov"));
    }

    while pos < iovcnt {
        // 确保访问的是有效的 iov[pos]
        if pos >= iov_len {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "pos exceeds the length of iov"));
        }

        let res = f(fd, &mut iov[pos])?;

        match res {
            0 => {
                return Err(io::Error::new(io::ErrorKind::BrokenPipe, "Broken pipe"));
            }
            _ => {
                pos += res;
            }
        }

        if let Some(callback) = cb {
            // 使用 `as_mut()` 来借用 cb_arg 而不是移动它
            if let Some(ref mut arg) = cb_arg.as_mut() {
                if callback(arg, res) == -1 {
                    return Err(io::Error::new(io::ErrorKind::Interrupted, "Interrupted by callback"));
                }
            }
        }
    }

    Ok(pos)
}

/// Simplified version of atomiciov6 that does not use callbacks.
pub fn atomiciov(
    f: fn(RawFd, &mut [u8]) -> io::Result<usize>,
    fd: RawFd,
    iov: &mut [Vec<u8>],
    iovcnt: usize,
) -> Result<usize, io::Error> {
    atomiciov6(f, fd, iov, iovcnt, None, None)
}

// 这是一个安全的 `write` 函数，接受可变引用
pub fn safe_write_mut(fd: RawFd, buf: &mut [u8]) -> io::Result<usize> {
    use std::os::unix::io::AsRawFd;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write(buf)
}


/// vwrite function equivalent in Rust
pub fn vwrite(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
    use std::os::unix::io::AsRawFd;
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write(buf)
}