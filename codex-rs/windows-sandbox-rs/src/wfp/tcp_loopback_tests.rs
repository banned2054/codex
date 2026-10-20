use super::*;
use std::collections::BTreeSet;
use std::net::{Ipv4Addr, Ipv6Addr};

fn guid_key(key: &GUID) -> (u32, u16, u16, [u8; 8]) {
    (key.data1, key.data2, key.data3, key.data4)
}

#[test]
fn tcp_loopback_keys_and_names_never_replace_strict_filters() {
    let strict = filter_specs::specs_for_mode(false);
    let loopback = filter_specs::specs_for_mode(true);
    assert_eq!(strict.len(), 16);
    assert_eq!(loopback.len(), 17);
    let keys = strict
        .iter()
        .chain(&loopback)
        .map(|s| guid_key(&s.key))
        .collect::<BTreeSet<_>>();
    let names = strict
        .iter()
        .chain(&loopback)
        .map(|s| s.name)
        .collect::<BTreeSet<_>>();
    assert_eq!(keys.len(), strict.len() + loopback.len());
    assert_eq!(names.len(), keys.len());
}

#[test]
fn tcp_loopback_leaves_udp_dns_and_smb_blocks_unconditional() {
    let specs = filter_specs::specs_for_mode(true);
    for name in [
        "udp_connect_v4",
        "udp_connect_v6",
        "dns_53_v4",
        "dns_53_v6",
        "dns_853_v4",
        "dns_853_v6",
        "smb_139_v4",
        "smb_139_v6",
        "smb_445_v4",
        "smb_445_v6",
    ] {
        let spec = specs.iter().find(|s| s.name.ends_with(name)).unwrap();
        assert_eq!(spec.conditions.len(), 2);
        assert!(matches!(spec.conditions[0], ConditionSpec::User));
    }
}

#[test]
fn tcp_loopback_native_conditions_block_external_and_lan_addresses_but_exclude_loopback() {
    let addresses = AddressConditions::new();
    let user = UserMatchCondition {
        security_descriptor: null_mut(),
        blob: empty_blob(),
    };
    let specs = filter_specs::specs_for_mode(true);
    let v4 = specs
        .iter()
        .filter(|s| s.name.contains("tcp_connect_v4"))
        .map(|s| {
            let conditions = build_conditions(s.conditions, &user, &addresses);
            let condition = conditions.last().unwrap();
            assert_eq!(condition.matchType, FWP_MATCH_RANGE);
            assert_eq!(condition.conditionValue.r#type, FWP_RANGE_TYPE);
            let range = unsafe { &*condition.conditionValue.Anonymous.rangeValue };
            assert_eq!(range.valueLow.r#type, FWP_UINT32);
            unsafe {
                (
                    range.valueLow.Anonymous.uint32,
                    range.valueHigh.Anonymous.uint32,
                )
            }
        })
        .collect::<Vec<_>>();
    for (address, blocked) in [
        ("0.0.0.0", true),
        ("1.1.1.1", true),
        ("126.255.255.255", true),
        ("127.0.0.0", false),
        ("127.0.0.1", false),
        ("127.255.255.255", false),
        ("128.0.0.0", true),
        ("192.168.8.248", true),
        ("255.255.255.255", true),
    ] {
        let value = u32::from(address.parse::<Ipv4Addr>().unwrap());
        assert_eq!(
            v4.iter().any(|(low, high)| (*low..=*high).contains(&value)),
            blocked,
            "{address}"
        );
    }
    let spec = specs
        .iter()
        .find(|s| s.name.ends_with("tcp_connect_v6"))
        .unwrap();
    let conditions = build_conditions(spec.conditions, &user, &addresses);
    let condition = conditions.last().unwrap();
    assert_eq!(condition.matchType, FWP_MATCH_NOT_EQUAL);
    assert_eq!(condition.conditionValue.r#type, FWP_BYTE_ARRAY16_TYPE);
    let excluded = unsafe { (*condition.conditionValue.Anonymous.byteArray16).byteArray16 };
    assert_eq!(excluded, Ipv6Addr::LOCALHOST.octets());
    for address in ["::", "::2", "fe80::1", "2001:db8::1", "::ffff:127.0.0.1"] {
        assert_ne!(
            excluded,
            address.parse::<Ipv6Addr>().unwrap().octets(),
            "{address}"
        );
    }
}
