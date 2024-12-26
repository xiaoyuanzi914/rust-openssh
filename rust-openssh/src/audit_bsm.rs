use std::ffi::CString;
use std::io::{self, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;
use std::ptr;
use std::os::unix::io::RawFd;
use std::string::String;

#[cfg(target_family = "unix")]
extern crate libc;

#[derive(Debug)]
struct AuditInfo {
    auid: i32,
    asid: i32,
    mask: AuditMask,
    termid: i32, // ssh_bsm_tid 相当于
}

#[derive(Debug)]
struct AuditMask {
    am_success: u32,
    am_failure: u32,
}

#[derive(Debug)]
pub enum AuditEvent {
    SuccessLogin,
    FailedLogin,
    SessionClosed,
    // 你可以根据需要添加更多的事件类型
}

#[cfg(target_family = "unix")]
extern "C" {
    fn getaddrinfo(
        node: *const libc::c_char,
        service: *const libc::c_char,
        hints: *const libc::addrinfo,
        res: *mut *mut libc::addrinfo,
    ) -> libc::c_int;

    fn freeaddrinfo(res: *mut libc::addrinfo);
}

fn debug3(message: &str) {
    eprintln!("{}", message);
}

fn bsm_audit_record(typ: i32, string: &str, event_no: i32) {
    debug3(&format!("BSM audit: typ {} rc {} \"{}\"", typ, 0, string));
    // 这里应该是将审计记录发送出去，可以根据实际需要实现 au_write
}

fn bsm_audit_session_setup(user: &str) {
    let mut mask = AuditMask { am_success: 0, am_failure: 0 };
    // 设置审计标志等
    debug3(&format!("BSM audit: session setup for user {}", user));
}

fn bsm_audit_bad_login(what: &str, user: &str) {
    let text = format!("invalid {} for user {}", what, user);
    bsm_audit_record(4, &text, 32800); // AUE_openssh = 32800
}

fn aug_get_machine(host: &str) -> io::Result<(IpAddr, u32)> {
    let mut addr_info: *mut libc::addrinfo = std::ptr::null_mut(); // 可变指针
    let c_host = CString::new(host).unwrap();

    unsafe {
        let res = getaddrinfo(c_host.as_ptr(), std::ptr::null(), std::ptr::null(), &mut addr_info); // 使用 &mut addr_info
        if res != 0 {
            return Err(io::Error::new(io::ErrorKind::Other, "getaddrinfo failed"));
        }

        let ai = *addr_info; // 获取地址信息
        let ip = match ai.ai_family {
            libc::AF_INET => {
                let sockaddr_in = &*(ai.ai_addr as *const libc::sockaddr_in);
                IpAddr::V4(Ipv4Addr::from(u32::from_be(sockaddr_in.sin_addr.s_addr)))
            }
            libc::AF_INET6 => {
                let sockaddr_in6 = &*(ai.ai_addr as *const libc::sockaddr_in6);
                IpAddr::V6(Ipv6Addr::from(sockaddr_in6.sin6_addr.s6_addr))
            }
            _ => return Err(io::Error::new(io::ErrorKind::Other, "Unknown address family")),
        };

        freeaddrinfo(addr_info); // 释放分配的内存
        Ok((ip, ai.ai_family as u32))
    }
}


fn selected(username: Option<&str>, uid: i32, event: AuditEvent, sf: i32) -> i32 {
    let mask = if let Some(username) = username {
        // 获取用户的审计标志
        AuditMask { am_success: 1, am_failure: 0 }
    } else {
        // 默认的标志
        AuditMask { am_success: 0, am_failure: 0 }
    };

    let sorf = if sf == 0 { 1 } else { 0 };
    // 检查事件是否已选择进行审计
    if sorf == 1 { 1 } else { 0 }
}

// 将函数设置为 `pub`，这样它可以在 `main.rs` 中访问
pub fn audit_connection_from(host: &str, port: i32) {
    debug3(&format!("BSM audit: connection from {} port {}", host, port));

    match aug_get_machine(host) {
        Ok((ip, _)) => debug3(&format!("BSM audit: machine ID {}", ip)),
        Err(_) => debug3("BSM audit: failed to get machine info"),
    }
}

pub fn audit_event(event: AuditEvent) {
    let user = "(unknown user)"; // 示例，实际可以从上下文中获取
    let text = match event {
        AuditEvent::SuccessLogin => format!("successful login {}", user),
        AuditEvent::FailedLogin => format!("failed login attempt {}", user),
        AuditEvent::SessionClosed => format!("session closed for {}", user),
    };

    bsm_audit_record(0, &text, 32800);
}

// 导出函数，供 `main.rs` 使用
pub fn audit_connection_from_host(host: &str, port: i32) {
    audit_connection_from(host, port);
}

pub fn audit_login_event(event: AuditEvent) {
    audit_event(event);
}
