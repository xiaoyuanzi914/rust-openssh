
use krb5_sys::*;
use libc::{c_int, c_char};
use log::{debug};
use std::ffi::CString;
use std::os::unix::io::RawFd;
use krb5_sys::krb5_context;
use krb5_sys::krb5_principal;
use krb5_sys::krb5_ccache;
use krb5_sys::krb5_error_code;
use krb5_sys::krb5_init_context;
use krb5_sys::krb5_parse_name;
use krb5_sys::krb5_cc_new_unique;
use krb5_sys::krb5_cc_initialize;
use krb5_sys::krb5_cc_resolve;
use krb5_sys::krb5_cc_destroy;
use krb5_sys::krb5_free_principal;
use krb5_sys::krb5_free_context;

#[cfg(feature = "krb5")]
extern crate krb5_sys;
#[cfg(feature = "krb5")]
use krb5_sys::{krb5_context, krb5_error_code, krb5_principal, krb5_ccache, krb5_creds, 
               krb5_init_context, krb5_parse_name, krb5_sname_to_principal, 
               krb5_cc_initialize, krb5_cc_new_unique, krb5_cc_copy_cache, 
               krb5_cc_destroy, krb5_get_error_message, krb5_verify_user, 
               krb5_cc_resolve, krb5_free_principal, krb5_free_context};

/// Struct that holds Kerberos context and authentication state
pub struct AuthCtxt {
    pub krb5_ctx: Option<krb5_context>,
    pub krb5_user: Option<krb5_principal>,
    pub krb5_fwd_ccache: Option<krb5_ccache>,
    pub krb5_ticket_file: Option<String>,
    pub krb5_ccname: Option<String>,
    pub pw_name: String, // Username
    pub valid: bool,     // Whether the user is valid
}

use std::ptr;
use krb5_sys::*;

impl AuthCtxt {
    pub fn krb5_init(&mut self) -> Result<(), krb5_error_code> {
        let context = self.krb5_ctx.unwrap();

        // 假设 krb5_user 存储了 principal 数据（用户名）
        let mut krb5_user_ptr: *mut krb5_principal_data = ptr::null_mut();

        // 获取用户名，从 krb5_user 中提取
        // 假设 krb5_user 是一个 Option<*mut krb5_principal_data>
        let krb5_user_name = if let Some(user_ptr) = self.krb5_user {
            unsafe {
                let user_name = krb5_principal_get_name(user_ptr);
                CString::from_raw(user_name as *mut i8).to_string_lossy().into_owned()
            }
        } else {
            return Err(krb5_error_code::from(1)); // 返回错误，表示用户名为空
        };

        let cname = CString::new(krb5_user_name).unwrap();  // 从krb5_user获取用户名

        // 调用 krb5_parse_name 函数，解析用户名
        let problem = unsafe {
            krb5_parse_name(context, cname.as_ptr(), &mut krb5_user_ptr)
        };

        if problem != 0 {
            return Err(problem);
        }

        self.krb5_user = Some(krb5_user_ptr);

        // 正确处理 ccache，使用 krb5_ccache 类型
        let mut ccache: *mut krb5_ccache = ptr::null_mut();
        let problem = unsafe {
            krb5_cc_new_unique(
                context,
                std::ptr::null(), // 假设这是正确的值
                ptr::null_mut(),  // 这可能需要根据需求修改
                ccache,
            )
        };

        if problem != 0 {
            return Err(problem);
        }

        self.krb5_fwd_ccache = Some(*ccache);

        Ok(())
    }

    pub fn krb5_cleanup_proc(&mut self) {
        // 清理 krb5_user（用户名）
        if let Some(krb5_user) = self.krb5_user {
            unsafe {
                krb5_free_principal(self.krb5_ctx.unwrap(), krb5_user);
            }
        }

        // 清理 krb5_fwd_ccache（凭证缓存）
        if let Some(krb5_fwd_ccache) = self.krb5_fwd_ccache {
            unsafe {
                krb5_cc_destroy(self.krb5_ctx.unwrap(), krb5_fwd_ccache);
            }
        }

        // 清理 krb5_ctx（上下文）
        if let Some(krb5_ctx) = self.krb5_ctx.take() {
            unsafe {
                krb5_free_context(krb5_ctx);
            }
        }
    }
}



// Placeholder for platform-specific Kerberos principal name retrieval
fn platform_krb5_get_principal_name(username: &str) -> Option<String> {
    Some(username.to_string()) // In a real-world scenario, adjust this as necessary
}

// Cleanup function to free Kerberos resources
pub fn krb5_cleanup_proc(authctxt: &mut AuthCtxt) {
    debug!("krb5_cleanup_proc called");

    if let Some(ccache) = authctxt.krb5_fwd_ccache {
        unsafe {
            krb5_cc_destroy(authctxt.krb5_ctx.unwrap(), ccache);
        }
    }

    if let Some(user) = authctxt.krb5_user {
        unsafe {
            krb5_free_principal(authctxt.krb5_ctx.unwrap(), user);
        }
    }

    if let Some(ctx) = authctxt.krb5_ctx {
        unsafe {
            krb5_free_context(ctx);
        }
    }

    authctxt.krb5_ctx = None;
    authctxt.krb5_user = None;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_krb5_password_success() {
        let mut authctxt = AuthCtxt {
            krb5_ctx: None,
            krb5_user: None,
            krb5_fwd_ccache: None,
            krb5_ticket_file: None,
            krb5_ccname: None,
            pw_name: "user".to_string(),
            valid: false,
        };

        let password = "password";
        let result = authctxt.auth_krb5_password(password);

        assert_eq!(result, 1);
        assert!(authctxt.valid);
    }

    #[test]
    fn test_auth_krb5_password_failure() {
        let mut authctxt = AuthCtxt {
            krb5_ctx: None,
            krb5_user: None,
            krb5_fwd_ccache: None,
            krb5_ticket_file: None,
            krb5_ccname: None,
            pw_name: "invalid_user".to_string(),
            valid: false,
        };

        let password = "wrong_password";
        let result = authctxt.auth_krb5_password(password);

        assert_eq!(result, 0);
        assert!(!authctxt.valid);
    }
}
