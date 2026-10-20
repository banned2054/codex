use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V6;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6;
use windows_sys::Win32::Networking::WinSock::IPPROTO_ICMP;
use windows_sys::Win32::Networking::WinSock::IPPROTO_ICMPV6;
use windows_sys::Win32::Networking::WinSock::IPPROTO_TCP;
use windows_sys::Win32::Networking::WinSock::IPPROTO_UDP;
use windows_sys::core::GUID;

#[derive(Clone, Copy)]
pub(super) enum ConditionSpec {
    User,
    Protocol(u8),
    RemotePort(u16),
    NonLoopbackV4Low,
    NonLoopbackV4High,
    NonLoopbackV6,
}

#[derive(Clone, Copy)]
pub(super) struct FilterSpec {
    pub(super) key: GUID,
    pub(super) name: &'static str,
    pub(super) description: &'static str,
    pub(super) layer_key: GUID,
    pub(super) conditions: &'static [ConditionSpec],
}

// Filter keys are TinyHarness-owned GUIDs defined in branding; install removes
// and re-adds by key, so a key shared with Codex would delete Codex's filters.
pub(super) const FILTER_SPECS: &[FilterSpec] = &[
    FilterSpec {
        key: crate::branding::WFP_FILTER_ICMP_CONNECT_V4_KEY,
        name: "tinyharness_wfp_icmp_connect_v4",
        description: "Block sandbox-account ICMP connect v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_ICMP as u8),
        ],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_ICMP_CONNECT_V6_KEY,
        name: "tinyharness_wfp_icmp_connect_v6",
        description: "Block sandbox-account ICMP connect v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_ICMPV6 as u8),
        ],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_ICMP_ASSIGN_V4_KEY,
        name: "tinyharness_wfp_icmp_assign_v4",
        description: "Block sandbox-account ICMP resource assignment v4",
        layer_key: FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V4,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_ICMP as u8),
        ],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_ICMP_ASSIGN_V6_KEY,
        name: "tinyharness_wfp_icmp_assign_v6",
        description: "Block sandbox-account ICMP resource assignment v6",
        layer_key: FWPM_LAYER_ALE_RESOURCE_ASSIGNMENT_V6,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_ICMPV6 as u8),
        ],
    },
    // NAME_RESOLUTION_CACHE filters are intentionally omitted because ordinary
    // static filter shapes returned FWP_E_OUT_OF_BOUNDS during validation.
    FilterSpec {
        key: crate::branding::WFP_FILTER_DNS_53_V4_KEY,
        name: "tinyharness_wfp_dns_53_v4",
        description: "Block sandbox-account DNS TCP or UDP port 53 v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(53)],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_DNS_53_V6_KEY,
        name: "tinyharness_wfp_dns_53_v6",
        description: "Block sandbox-account DNS TCP or UDP port 53 v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(53)],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_DNS_853_V4_KEY,
        name: "tinyharness_wfp_dns_853_v4",
        description: "Block sandbox-account DNS-over-TLS port 853 v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(853)],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_DNS_853_V6_KEY,
        name: "tinyharness_wfp_dns_853_v6",
        description: "Block sandbox-account DNS-over-TLS port 853 v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(853)],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_SMB_445_V4_KEY,
        name: "tinyharness_wfp_smb_445_v4",
        description: "Block sandbox-account SMB port 445 v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(445)],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_SMB_445_V6_KEY,
        name: "tinyharness_wfp_smb_445_v6",
        description: "Block sandbox-account SMB port 445 v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(445)],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_SMB_139_V4_KEY,
        name: "tinyharness_wfp_smb_139_v4",
        description: "Block sandbox-account SMB port 139 v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(139)],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_SMB_139_V6_KEY,
        name: "tinyharness_wfp_smb_139_v6",
        description: "Block sandbox-account SMB port 139 v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[ConditionSpec::User, ConditionSpec::RemotePort(139)],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_TCP_CONNECT_V4_KEY,
        name: "tinyharness_wfp_tcp_connect_v4",
        description: "Block sandbox-account outbound TCP v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_TCP as u8),
        ],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_TCP_CONNECT_V6_KEY,
        name: "tinyharness_wfp_tcp_connect_v6",
        description: "Block sandbox-account outbound TCP v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_TCP as u8),
        ],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_UDP_CONNECT_V4_KEY,
        name: "tinyharness_wfp_udp_connect_v4",
        description: "Block sandbox-account outbound UDP v4",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V4,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_UDP as u8),
        ],
    },
    FilterSpec {
        key: crate::branding::WFP_FILTER_UDP_CONNECT_V6_KEY,
        name: "tinyharness_wfp_udp_connect_v6",
        description: "Block sandbox-account outbound UDP v6",
        layer_key: FWPM_LAYER_ALE_AUTH_CONNECT_V6,
        conditions: &[
            ConditionSpec::User,
            ConditionSpec::Protocol(IPPROTO_UDP as u8),
        ],
    },
];

// 独立模式使用独立 key，安装时绝不删除或重绑定严格模式的过滤器。
const TCP_LOOPBACK_IDENTITIES: &[(GUID, &str)] = &[
    (
        GUID::from_u128(0x0712b4aac7cd5003b75498a871bf12f2),
        "tinyharness_tcp_loopback_wfp_icmp_connect_v4",
    ),
    (
        GUID::from_u128(0x2f92b9de699e55d98393a15839b85d40),
        "tinyharness_tcp_loopback_wfp_icmp_connect_v6",
    ),
    (
        GUID::from_u128(0xac1b1bda91a758ddbcd96356070e3ac1),
        "tinyharness_tcp_loopback_wfp_icmp_assign_v4",
    ),
    (
        GUID::from_u128(0x337435949c7755778c3d74d0f30b0a03),
        "tinyharness_tcp_loopback_wfp_icmp_assign_v6",
    ),
    (
        GUID::from_u128(0x26d305caeb615c1abed94d13c333f270),
        "tinyharness_tcp_loopback_wfp_dns_53_v4",
    ),
    (
        GUID::from_u128(0x834984854b8153a0a7dc5bd6399a89b7),
        "tinyharness_tcp_loopback_wfp_dns_53_v6",
    ),
    (
        GUID::from_u128(0x311876b5667e56d6b1f9dbba1a59d959),
        "tinyharness_tcp_loopback_wfp_dns_853_v4",
    ),
    (
        GUID::from_u128(0x633a2654d3a35cdc9fdea150c4f945d5),
        "tinyharness_tcp_loopback_wfp_dns_853_v6",
    ),
    (
        GUID::from_u128(0x4b7749ad19c558aca41c95c84831c7f0),
        "tinyharness_tcp_loopback_wfp_smb_445_v4",
    ),
    (
        GUID::from_u128(0x3f708f48937d5264bff977a837eb008c),
        "tinyharness_tcp_loopback_wfp_smb_445_v6",
    ),
    (
        GUID::from_u128(0xaca327d4a9225d8f8d2b90094333651b),
        "tinyharness_tcp_loopback_wfp_smb_139_v4",
    ),
    (
        GUID::from_u128(0x69f257cdec9b5d50b8ff08f455db990d),
        "tinyharness_tcp_loopback_wfp_smb_139_v6",
    ),
    (
        GUID::from_u128(0xb4a0eab4cc9e5d3fbb32c6f9f9dedb5e),
        "tinyharness_tcp_loopback_wfp_tcp_connect_v4",
    ),
    (
        GUID::from_u128(0x5929687894a5521f8543e8bf2f2c8eaf),
        "tinyharness_tcp_loopback_wfp_tcp_connect_v6",
    ),
    (
        GUID::from_u128(0xd2a0f9b745915b6596bab093070d3b89),
        "tinyharness_tcp_loopback_wfp_udp_connect_v4",
    ),
    (
        GUID::from_u128(0x0aa310236626592983fa1fe685c70fbc),
        "tinyharness_tcp_loopback_wfp_udp_connect_v6",
    ),
    (
        GUID::from_u128(0xc1970aae0f4756079cf4581f347b2d97),
        "tinyharness_tcp_loopback_wfp_tcp_connect_v4_high",
    ),
];

pub(super) fn specs_for_mode(allow_tcp_loopback: bool) -> Vec<FilterSpec> {
    if !allow_tcp_loopback {
        return FILTER_SPECS.to_vec();
    }
    let mut result = Vec::new();
    for (index, original) in FILTER_SPECS.iter().enumerate() {
        let mut spec = *original;
        (spec.key, spec.name) = TCP_LOOPBACK_IDENTITIES[index];
        if original.name == "tinyharness_wfp_tcp_connect_v4" {
            spec.conditions = &[
                ConditionSpec::User,
                ConditionSpec::Protocol(IPPROTO_TCP as u8),
                ConditionSpec::NonLoopbackV4Low,
            ];
            let mut high = spec;
            (high.key, high.name) = TCP_LOOPBACK_IDENTITIES[FILTER_SPECS.len()];
            high.conditions = &[
                ConditionSpec::User,
                ConditionSpec::Protocol(IPPROTO_TCP as u8),
                ConditionSpec::NonLoopbackV4High,
            ];
            result.push(high);
        } else if original.name == "tinyharness_wfp_tcp_connect_v6" {
            spec.conditions = &[
                ConditionSpec::User,
                ConditionSpec::Protocol(IPPROTO_TCP as u8),
                ConditionSpec::NonLoopbackV6,
            ];
        }
        result.push(spec);
    }
    result
}
