use std::net::{Ipv4Addr, Ipv6Addr};
use std::str::FromStr;
use regex::Regex;
use log::{Level, LevelFilter, log, error, debug, info, trace, warn};
use std::time::Duration;
use std::time::Instant;
use std::sync::{Arc, Mutex};
use std::fmt;

#[derive(Debug)]
pub struct XAddr {
    pub af: u16,           // Address family
    pub xa: XAddrUnion,    // The union that stores address data
    pub scope_id: u32,     // Scope ID (used in IPv6)
}

pub union XAddrUnion {
    pub v4: std::net::Ipv4Addr,
    pub v6: std::net::Ipv6Addr,
    pub addr8: [u8; 16],
    pub addr16: [u16; 8],
    pub addr32: [u32; 4],
}
impl fmt::Debug for XAddrUnion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        unsafe {
            // 试图打印 IPv4 或 IPv6 地址，其他字段可以根据需要进行添加
            f.debug_struct("XAddrUnion")
                .field("v4", &self.v4) // 在这个地方确保 `v4` 字段是有效的
                .field("v6", &self.v6) // 或者你也可以选择 `v6` 字段
                .finish()
        }
    }
}

pub const AF_INET: u16 = 2;   // IPv4
pub const AF_INET6: u16 = 10; // IPv6

// Helper function to mimic C's addr_pton function
pub fn addr_pton(addr: &str) -> Result<XAddr, &'static str> {
    if let Ok(v4) = Ipv4Addr::from_str(addr) {
        return Ok(XAddr {
            af: AF_INET,
            xa: XAddrUnion { v4 },
            scope_id: 0,
        });
    } else if let Ok(v6) = Ipv6Addr::from_str(addr) {
        return Ok(XAddr {
            af: AF_INET6,
            xa: XAddrUnion { v6 },
            scope_id: 0,
        });
    }
    Err("Invalid address format")
}

// Helper function to mimic C's addr_pton_cidr function
pub fn addr_pton_cidr(cidr: &str) -> Result<(XAddr, u32), &'static str> {
    let parts: Vec<&str> = cidr.split('/').collect();
    if parts.len() != 2 {
        return Err("Invalid CIDR format");
    }

    let addr = addr_pton(parts[0])?;
    let masklen = parts[1].parse::<u32>().map_err(|_| "Invalid mask length")?;

    Ok((addr, masklen))
}

// Helper function to match addresses
pub fn addr_netmatch(addr: &XAddr, match_addr: &XAddr, masklen: u32) -> bool {
    // We assume here that the addresses are of the same family (either both IPv4 or both IPv6)
    match addr.af {
        AF_INET => {
            // 使用 unsafe 块访问 union 的 v4 字段
            if unsafe { addr.xa.v4 } != Ipv4Addr::new(0, 0, 0, 0) {
                if unsafe { match_addr.xa.v4 } != Ipv4Addr::new(0, 0, 0, 0) {
                    // Perform bitwise comparison for IPv4 address matching
                    let mask = !((1 << (32 - masklen)) - 1);
                    let addr_u32 = u32::from(unsafe { addr.xa.v4 });
                    let match_u32 = u32::from(unsafe { match_addr.xa.v4 });
                    return (addr_u32 & mask) == (match_u32 & mask);
                }
            }
        }
        AF_INET6 => {
            // 使用 unsafe 块访问 union 的 v6 字段
            if unsafe { addr.xa.v6 } != Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0) {
                if unsafe { match_addr.xa.v6 } != Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0) {
                    // Perform bitwise comparison for IPv6 address matching
                    let mask = !((1 << (128 - masklen)) - 1);
                    let addr_u128 = u128::from(unsafe { addr.xa.v6 });
                    let match_u128 = u128::from(unsafe { match_addr.xa.v6 });
                    return (addr_u128 & mask) == (match_u128 & mask);
                }
            }
        }
        _ => {}
    }
    false
}

// Add logging functionality
pub fn addr_match_list(addr: Option<&str>, _list: &str) -> i32 {
    let mut ret = 0;
    let mut o = _list.to_string();
    let mut list = o.split(',');

    let try_addr = match addr {
        Some(addr_str) => match addr_pton(addr_str) {
            Ok(addr) => addr,
            Err(_) => return 0,
        },
        None => return 0,
    };

    for cp in list {
        let neg = cp.starts_with('!');
        let cp = if neg { &cp[1..] } else { cp };

        if cp.is_empty() {
            ret = -2;
            break;
        }

        // Prefer CIDR address matching
        match addr_pton_cidr(cp) {
            Ok((match_addr, masklen)) => {
                if addr_netmatch(&try_addr, &match_addr, masklen) {
                    if neg {
                        ret = -1;
                        break;
                    } else {
                        ret = 1;
                    }
                }
            }
            Err(_) => {
                // Fallback to wildcard matching if CIDR fails
                if addr_match_wildcard(addr.unwrap_or(""), cp) {
                    if neg {
                        ret = -1;
                        break;
                    } else {
                        ret = 1;
                    }
                }
            }
        }
    }

    ret
}

pub fn addr_match_cidr_list(addr: Option<&str>, _list: &str) -> i32 {
    let mut ret = 0;
    let mut o = _list.to_string();
    let mut list = o.split(',');

    let try_addr = match addr {
        Some(addr_str) => match addr_pton(addr_str) {
            Ok(addr) => addr,
            Err(_) => return 0,
        },
        None => return 0,
    };

    for cp in list {
        if cp.is_empty() {
            return -1;
        }

        // Validate CIDR entry
        if !cp.chars().all(|c| "0123456789abcdefABCDEF.:/".contains(c)) {
            return -1;
        }

        match addr_pton_cidr(cp) {
            Ok((match_addr, masklen)) => {
                if addr_netmatch(&try_addr, &match_addr, masklen) {
                    ret = 1;
                }
            }
            Err(_) => return -1,
        }
    }

    ret
}

fn addr_match_wildcard(addr: &str, pattern: &str) -> bool {
    // Implement a pattern matching for wildcards (e.g., using regex or basic string matching)
    let regex_pattern = convert_wildcard_to_regex(pattern);
    let re = Regex::new(&regex_pattern).unwrap();
    re.is_match(addr)
}

// Convert simple wildcard patterns to regex
fn convert_wildcard_to_regex(pattern: &str) -> String {
    pattern.replace('*', ".*").replace('?', ".")
}

// Log initialization (simple log wrapper for simplicity)
pub fn log_init(level: Level, threshold: Option<Duration>, facility: Option<String>) {
    // Set up logging configuration (you can use env_logger or other logging crates)
    std::env::set_var("RUST_LOG", level.to_string());
    env_logger::init();
    
    // You could add more setup logic here (for example, logging to specific facilities)
    debug!("Logging initialized with level: {:?}", level);
}

// Log rate limiting context
pub struct LogRateLimitCtx {
    pub threshold: u32,
    pub max_accum: u32,
    pub hysteresis: u32,
    pub log_every: u32,
    
    // 为 Instant 实现 Default，直接使用 `Instant::now()` 作为默认值
    pub last_event: Instant,
    pub accumulated_events: u32,
    pub ratelimit_active: i32,
    pub ratelimit_start: Instant,
    pub last_log: Instant,
    pub hysteresis_start: Instant,
    pub ratelimited_events: u32,
}

impl Default for LogRateLimitCtx {
    fn default() -> Self {
        LogRateLimitCtx {
            threshold: 0,
            max_accum: 0,
            hysteresis: 0,
            log_every: 0,
            last_event: Instant::now(),
            accumulated_events: 0,
            ratelimit_active: 0,
            ratelimit_start: Instant::now(),
            last_log: Instant::now(),
            hysteresis_start: Instant::now(),
            ratelimited_events: 0,
        }
    }
}
