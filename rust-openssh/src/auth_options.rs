use std::ffi::CString;
use std::ptr;
use std::vec::Vec;
use std::alloc::{self, Layout};
use std::collections::HashMap;
use std::io::{self, Write};
use std::str::FromStr;

// Function to duplicate a list of strings
fn dup_strings(src: &[&str]) -> Result<Vec<String>, std::io::Error> {
    let mut dst: Vec<String> = Vec::with_capacity(src.len());

    for &s in src {
        match CString::new(s) {
            Ok(cstr) => {
                dst.push(cstr.into_string().unwrap());
            }
            Err(_) => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "Failed to duplicate string",
                ));
            }
        }
    }

    Ok(dst)
}


#[derive(Default)]
struct SshAuthOpt {
    no_require_user_presence: bool,
    permit_x11_forwarding_flag: bool,
    permit_agent_forwarding_flag: bool,
    permit_port_forwarding_flag: bool,
    permit_pty_flag: bool,
    permit_user_rc: bool,
    require_verify: bool,
    force_command: Option<String>,
    required_from_host_cert: Option<String>,
}

#[derive(Debug)]
pub enum ParseError {
    InvalidBuffer,
    InvalidOption,
    MultipleOptions(String),
    SyntaxError(String),
    OptionCorruption,
}

const OPTIONS_CRITICAL: u32 = 1;
const OPTIONS_EXTENSIONS: u32 = 2;

fn addr_match_cidr_list(_allowed: Option<String>) -> Result<(), ParseError> {
    // Stub for CIDR address matching logic
    Ok(())
}

fn cert_option_list(
    opts: &mut SshAuthOpt,
    oblob: &[u8],
    which: u32,
    crit: bool,
) -> Result<(), ParseError> {
    let mut c = oblob.to_vec();
    let mut found = false;
    let mut i = 0;

    while i < c.len() {
        let mut name = String::new();
        let mut data = Vec::new();

        // Parse the option name (Assume length-prefixed for simplicity)
        if i + 4 > c.len() {
            return Err(ParseError::InvalidBuffer);
        }
        let len = u32::from_be_bytes(c[i..i + 4].try_into().unwrap()) as usize;
        i += 4;

        if i + len > c.len() {
            return Err(ParseError::InvalidBuffer);
        }
        name = String::from_utf8_lossy(&c[i..i + len]).to_string();
        i += len;

        // Parse the associated data
        if i + 4 > c.len() {
            return Err(ParseError::InvalidBuffer);
        }
        let data_len = u32::from_be_bytes(c[i..i + 4].try_into().unwrap()) as usize;
        i += 4;

        if i + data_len > c.len() {
            return Err(ParseError::InvalidBuffer);
        }
        data = c[i..i + data_len].to_vec();
        i += data_len;

        println!("Found certificate option \"{}\", len {}", name, data.len());
        found = false;

        // Check for extensions
        if (which & OPTIONS_EXTENSIONS) != 0 {
            match name.as_str() {
                "no-touch-required" => {
                    opts.no_require_user_presence = true;
                    found = true;
                }
                "permit-X11-forwarding" => {
                    opts.permit_x11_forwarding_flag = true;
                    found = true;
                }
                "permit-agent-forwarding" => {
                    opts.permit_agent_forwarding_flag = true;
                    found = true;
                }
                "permit-port-forwarding" => {
                    opts.permit_port_forwarding_flag = true;
                    found = true;
                }
                "permit-pty" => {
                    opts.permit_pty_flag = true;
                    found = true;
                }
                "permit-user-rc" => {
                    opts.permit_user_rc = true;
                    found = true;
                }
                _ => {}
            }
        }

        if !found && (which & OPTIONS_CRITICAL) != 0 {
            match name.as_str() {
                "verify-required" => {
                    opts.require_verify = true;
                    found = true;
                }
                "force-command" => {
                    let command = String::from_utf8_lossy(&data).to_string();
                    if opts.force_command.is_some() {
                        return Err(ParseError::MultipleOptions("force-command".to_string()));
                    }
                    opts.force_command = Some(command);
                    found = true;
                }
                "source-address" => {
                    let allowed = String::from_utf8_lossy(&data).to_string();
                    if opts.required_from_host_cert.is_some() {
                        return Err(ParseError::MultipleOptions("source-address".to_string()));
                    }
                    addr_match_cidr_list(Some(allowed.clone()))?; // Check syntax
                    opts.required_from_host_cert = Some(allowed);
                    found = true;
                }
                _ => {}
            }
        }

        if !found {
            if crit {
                return Err(ParseError::OptionCorruption);
            } else {
                println!("Certificate extension \"{}\" is not supported", name);
            }
        } else if !data.is_empty() {
            return Err(ParseError::OptionCorruption);
        }
    }

    Ok(())
}

#[derive(Default)]
pub struct SshAuthOpt {
    force_tun_device: i32,
    cert_principals: Option<Vec<String>>,
    force_command: Option<String>,
    required_from_host_cert: Option<String>,
    required_from_host_keys: Option<Vec<String>>,
    nenv: usize,
    env: Option<Vec<String>>,
    npermitopen: usize,
    permitopen: Option<Vec<String>>,
    npermitlisten: usize,
    permitlisten: Option<Vec<String>>,
    permit_port_forwarding_flag: bool,
    permit_agent_forwarding_flag: bool,
    permit_x11_forwarding_flag: bool,
    permit_pty_flag: bool,
    permit_user_rc: bool,
}

impl SshAuthOpt {
    // Equivalent to sshauthopt_new() in C
    pub fn new() -> Option<Box<Self>> {
        let mut ret = Box::new(SshAuthOpt::default());
        ret.force_tun_device = -1;
        Some(ret)
    }

    // Equivalent to sshauthopt_free() in C
    pub fn free(&mut self) {
        // Automatically freed when the struct is dropped. No need to manually free memory in Rust.
    }

    // Equivalent to sshauthopt_new_with_keys_defaults() in C
    pub fn new_with_keys_defaults() -> Option<Box<Self>> {
        let mut ret = SshAuthOpt::new()?;

        // Set defaults for the flags (same as in the C code)
        ret.permit_port_forwarding_flag = true;
        ret.permit_agent_forwarding_flag = true;
        ret.permit_x11_forwarding_flag = true;
        ret.permit_pty_flag = true;
        ret.permit_user_rc = true;

        Some(ret)
    }
}

#[derive(Debug)]
pub enum SshAuthError {
    TooManyPermissions,
    MemoryAllocationFailed,
    InvalidPermissionHostname,
    InvalidPermissionPort,
    UnknownError,
}

pub fn handle_permit(
    optsp: &mut Vec<String>,
    allow_bare_port: bool,
    permitsp: &mut Vec<String>,
    npermitsp: &mut usize,
) -> Result<(), SshAuthError> {
    if *npermitsp > SSH_AUTHOPT_PERMIT_MAX {
        return Err(SshAuthError::TooManyPermissions);
    }

    let opt = optsp.pop().ok_or(SshAuthError::UnknownError)?;
    let mut opt = opt.clone();

    if allow_bare_port && !opt.contains(':') {
        // Allow a bare port number in permitlisten to indicate a listen_host wildcard.
        opt = format!("*:{opt}");
    }

    let mut tmp = opt.clone();
    // Validate syntax before recording it.
    let host = match hpdelim2(&mut tmp) {
        Some(h) => h,
        None => return Err(SshAuthError::InvalidPermissionHostname),
    };

    if host.len() >= NI_MAXHOST {
        return Err(SshAuthError::InvalidPermissionHostname);
    }

    // Validate the port.
    let port = tmp.trim();
    if port != "*" && port.parse::<u16>().is_err() {
        return Err(SshAuthError::InvalidPermissionPort);
    }

    // Record the permission.
    permitsp.push(opt);

    *npermitsp += 1;

    Ok(())
}

// Helper function: mimicking `hpdelim2` from C
fn hpdelim2(input: &mut String) -> Option<String> {
    let parts: Vec<&str> = input.split(':').collect();
    if parts.is_empty() {
        return None;
    }
    Some(parts[0].to_string())  // Return the hostname part.
}

const SSH_AUTHOPT_PERMIT_MAX: usize = 100;  // Arbitrary value for max permission directives.
const NI_MAXHOST: usize = 256;  // Maximum allowed hostname length (example).