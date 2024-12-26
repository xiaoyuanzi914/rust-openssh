// audit.rs

use libc::{geteuid};  // 获取有效用户 ID (UID)
use std::ffi::CString;
use std::ptr;

#[derive(Debug, PartialEq, Copy, Clone)]  // 添加 Copy 和 Clone
pub enum SshAuditEvent {
    LoginExceedMaxTries,
    LoginRootDenied,
    AuthSuccess,
    AuthFailNone,
    AuthFailPasswd,
    AuthFailKbdInt,
    AuthFailPubKey,
    AuthFailHostBased,
    AuthFailGssApi,
    InvalidUser,
    NoLogin,
    ConnectionClose,
    ConnectionAbandon,
    AuditUnknown,
}


impl SshAuditEvent {
    pub fn lookup(&self) -> &'static str {
        match self {
            SshAuditEvent::LoginExceedMaxTries => "LOGIN_EXCEED_MAXTRIES",
            SshAuditEvent::LoginRootDenied => "LOGIN_ROOT_DENIED",
            SshAuditEvent::AuthSuccess => "AUTH_SUCCESS",
            SshAuditEvent::AuthFailNone => "AUTH_FAIL_NONE",
            SshAuditEvent::AuthFailPasswd => "AUTH_FAIL_PASSWD",
            SshAuditEvent::AuthFailKbdInt => "AUTH_FAIL_KBDINT",
            SshAuditEvent::AuthFailPubKey => "AUTH_FAIL_PUBKEY",
            SshAuditEvent::AuthFailHostBased => "AUTH_FAIL_HOSTBASED",
            SshAuditEvent::AuthFailGssApi => "AUTH_FAIL_GSSAPI",
            SshAuditEvent::InvalidUser => "INVALID_USER",
            SshAuditEvent::NoLogin => "NOLOGIN",
            SshAuditEvent::ConnectionClose => "CONNECTION_CLOSE",
            SshAuditEvent::ConnectionAbandon => "CONNECTION_ABANDON",
            SshAuditEvent::AuditUnknown => "AUDIT_UNKNOWN",
        }
    }
}

pub struct AuthContext {
    pub user: Option<String>,
    pub valid: bool,
}

pub struct LoginInfo {
    pub line: Option<String>,
}

pub fn audit_classify_auth(method: &str) -> SshAuditEvent {
    match method {
        "none" => SshAuditEvent::AuthFailNone,
        "password" => SshAuditEvent::AuthFailPasswd,
        "publickey" | "rsa" => SshAuditEvent::AuthFailPubKey,
        "keyboard-interactive" | "challenge-response" => SshAuditEvent::AuthFailKbdInt,
        "hostbased" | "rhosts-rsa" => SshAuditEvent::AuthFailHostBased,
        "gssapi-with-mic" => SshAuditEvent::AuthFailGssApi,
        _ => SshAuditEvent::AuditUnknown,
    }
}

pub fn audit_username(authctxt: Option<&AuthContext>) -> String {
    match authctxt {
        Some(ctxt) if ctxt.valid => ctxt.user.clone().unwrap_or("(unknown user)".to_string()),
        _ => "(unknown user)".to_string(),
    }
}

pub fn audit_connection_from(host: &str, port: i32) {
    println!("audit connection from {} port {} euid {}", host, port, unsafe { geteuid() });
}

pub fn audit_event(event: &SshAuditEvent) {
    // 使用引用方式打印枚举值，而不是尝试移动它
    println!(
        "audit event euid {} user {} event {} ({})",
        unsafe { geteuid() },
        audit_username(None),
        (*event as i32),  // 这里解引用 event 来获取其值并转换为 i32
        event.lookup()
    );
}


pub fn audit_session_open(li: &LoginInfo) {
    let tty = li.line.as_deref().unwrap_or("(no tty)");
    println!("audit session open euid {} user {} tty name {}", unsafe { geteuid() }, audit_username(None), tty);
}

pub fn audit_session_close(li: &LoginInfo) {
    let tty = li.line.as_deref().unwrap_or("(no tty)");
    println!("audit session close euid {} user {} tty name {}", unsafe { geteuid() }, audit_username(None), tty);
}

pub fn audit_run_command(command: &str) {
    // 限制命令字符串的最大长度为 200 个字符
    let truncated_command = if command.len() > 200 {
        &command[0..200]
    } else {
        command
    };

    println!(
        "audit run command euid {} user {} command '{}' ",
        unsafe { geteuid() },
        audit_username(None),
        truncated_command
    );
}
