#[cfg(test)]
mod tests;

use super::*;

#[test]
fn test_ipv4_netmask() {
    let mask = XAddr::netmask(4, 24);
    assert_eq!(mask, Some(XAddr::new_v4(Ipv4Addr::new(255, 255, 255, 0))));
}

#[test]
fn test_ipv6_netmask() {
    let mask = XAddr::netmask(6, 64);
    assert_eq!(
        mask,
        Some(XAddr::new_v6(Ipv6Addr::from([
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0x0000, 0x0000
        ])))
    );
}

#[test]
fn test_invalid_af() {
    // 测试无效的地址族
    let mask = XAddr::netmask(10, 24);
    assert_eq!(mask, None);
}

#[test]
fn test_ipv4_edge_case() {
    // 测试IPv4地址的边界
    let mask = XAddr::netmask(4, 32);
    assert_eq!(mask, Some(XAddr::new_v4(Ipv4Addr::new(255, 255, 255, 255))));
}

#[test]
fn test_ipv6_edge_case() {
    // 测试IPv6地址的边界
    let mask = XAddr::netmask(6, 128);
    assert_eq!(
        mask,
        Some(XAddr::new_v6(Ipv6Addr::from([
            0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff, 0xffff
        ])))
    );
}
