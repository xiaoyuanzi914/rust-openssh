extern crate libc;
use std::ffi::{CString, CStr};
use std::io::{self, Write};
use std::ptr;
use libc::{geteuid, EINVAL, EPROTONOSUPPORT, EAFNOSUPPORT, EPERM};

const AUDIT_USER_LOGIN: i32 = 1100; // 假设的审计事件类型

// 将 C 中的审计函数封装为 Rust 函数
extern "C" {
    fn audit_open() -> i32;
    fn audit_log_acct_message(
        fd: i32,
        type_: i32,
        addr: *const libc::c_char,
        msg: *const libc::c_char,
        user: *const libc::c_char,
        uid: i32,
        hostname: *const libc::c_char,
        ip: *const libc::c_char,
        tty: *const libc::c_char,
        success: i32,
    ) -> i32;
    fn close(fd: i32);
}

fn linux_audit_record_event(uid: i32, username: Option<&str>, hostname: Option<&str>, ip: Option<&str>, ttyn: Option<&str>, success: i32) -> Result<bool, io::Error> {
    unsafe {
        let audit_fd = audit_open();
        if audit_fd < 0 {
            // 捕获 `errno` 错误
            let err = io::Error::last_os_error(); // 获取 `errno`
            if err.raw_os_error() == Some(EINVAL) || err.raw_os_error() == Some(EPROTONOSUPPORT) || err.raw_os_error() == Some(EAFNOSUPPORT) {
                return Ok(true); // No audit support in kernel
            } else {
                return Ok(false); // Prevent login
            }
        }

        let username_cstr = CString::new(username.unwrap_or("(unknown)")).unwrap();
        let hostname_cstr = CString::new(hostname.unwrap_or("")).unwrap();
        let ip_cstr = CString::new(ip.unwrap_or("")).unwrap();
        let ttyn_cstr = CString::new(ttyn.unwrap_or("")).unwrap();

        let rc = audit_log_acct_message(
            audit_fd,
            AUDIT_USER_LOGIN,
            ptr::null(),
            CString::new("login").unwrap().as_ptr(),
            username_cstr.as_ptr(),
            if username.is_none() { uid } else { -1 },
            hostname_cstr.as_ptr(),
            ip_cstr.as_ptr(),
            ttyn_cstr.as_ptr(),
            success,
        );

        let saved_errno = io::Error::last_os_error(); // 保存当前的错误码
        close(audit_fd);

        if rc == -libc::EPERM && geteuid() != 0 {
            return Ok(false); // Don't report error if it's due to non-root user
        }

        // 恢复错误码
        if let Some(err) = saved_errno.raw_os_error() {
            std::process::abort(); // 如果有错误，处理错误
        }

        return Ok(rc >= 0);
    }
}

pub fn audit_connection_from(host: &str, port: i32) {
    // Not implemented in the C version
}

pub fn audit_run_command(command: &str) {
    // Not implemented in the C version
}

pub fn audit_session_open(li: &LoginInfo) {
    if let Err(e) = linux_audit_record_event(li.uid, None, Some(&li.hostname), None, Some(&li.line), 1) {
        eprintln!("linux_audit_write_entry failed: {}", e);
    }
}

pub fn audit_session_close(li: &LoginInfo) {
    // Not implemented in the C version
}

pub fn audit_event(ssh: &Ssh, event: SshAuditEvent) {
    match event {
        SshAuditEvent::SSH_AUTH_SUCCESS |
        SshAuditEvent::SSH_CONNECTION_CLOSE |
        SshAuditEvent::SSH_NOLOGIN |
        SshAuditEvent::SSH_LOGIN_EXCEED_MAXTRIES |
        SshAuditEvent::SSH_LOGIN_ROOT_DENIED => {}
        SshAuditEvent::SSH_AUTH_FAIL_NONE |
        SshAuditEvent::SSH_AUTH_FAIL_PASSWD |
        SshAuditEvent::SSH_AUTH_FAIL_KBDINT |
        SshAuditEvent::SSH_AUTH_FAIL_PUBKEY |
        SshAuditEvent::SSH_AUTH_FAIL_HOSTBASED |
        SshAuditEvent::SSH_AUTH_FAIL_GSSAPI |
        SshAuditEvent::SSH_INVALID_USER => {
            let remote_ip = ssh.remote_ipaddr();
            let username = audit_username();
            linux_audit_record_event(-1, Some(&username), None, Some(&remote_ip), Some("sshd"), 0).unwrap();
        }
        _ => {
            eprintln!("unhandled event {:?}", event);
        }
    }
}

// 结构体 LoginInfo 和相关函数（例如 ssh_remote_ipaddr）需要根据实际的应用场景进一步实现
// 假设的 LoginInfo 结构体和 SshAuditEvent 枚举
#[derive(Debug)]
pub struct LoginInfo {
    pub uid: i32,
    pub hostname: String,
    pub line: String,
}

#[derive(Debug)] // 让枚举实现 Debug
pub enum SshAuditEvent {
    SSH_AUTH_SUCCESS,
    SSH_CONNECTION_CLOSE,
    SSH_NOLOGIN,
    SSH_LOGIN_EXCEED_MAXTRIES,
    SSH_LOGIN_ROOT_DENIED,
    SSH_AUTH_FAIL_NONE,
    SSH_AUTH_FAIL_PASSWD,
    SSH_AUTH_FAIL_KBDINT,
    SSH_AUTH_FAIL_PUBKEY,
    SSH_AUTH_FAIL_HOSTBASED,
    SSH_AUTH_FAIL_GSSAPI,
    SSH_INVALID_USER,
}

pub struct Ssh {
    // 假设有一个方法获取远程 IP 地址
}

impl Ssh {
    pub fn remote_ipaddr(&self) -> String {
        "192.168.1.1".to_string() // 示例
    }
}

pub fn audit_username() -> String {
    "example_user".to_string() // 假设的用户名
}
