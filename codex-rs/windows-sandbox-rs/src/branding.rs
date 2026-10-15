//! Identity namespace owned by this build of the Windows sandbox.
//!
//! Every machine-wide name this code provisions lives here: local accounts, the
//! sandbox group, firewall rule lookup names, WFP objects, registry records, the
//! provisioning pipe, mutexes, private desktops, and the service name. This
//! build is the TinyHarness fork: it must coexist with an installed Codex
//! release, and sharing even one of these names makes the two installs fight
//! over it silently (a shared password slot, firewall rules rewritten to the
//! other install's SID, WFP filters deleted by the other's delete-then-add).
//! Do not reintroduce Codex-owned identifiers here.
//!
//! The WFP GUIDs are deterministic uuid5 derivations (name "TinyHarness",
//! namespace = the upstream Codex GUID) so they are reproducible and auditable
//! while remaining distinct from the Codex-owned values.

use windows_sys::core::GUID;

// Local accounts. SAM account names are limited to 20 characters.
pub const OFFLINE_USERNAME: &str = "TinyHarnessOffline";
pub const ONLINE_USERNAME: &str = "TinyHarnessOnline";
pub const SANDBOX_USERS_GROUP: &str = "TinyHarnessUsers";
pub const SANDBOX_USERS_GROUP_COMMENT: &str = "TinyHarness sandbox internal group (managed)";

// Firewall rule lookup names. These are the stable identifiers used to find
// and update the rules idempotently; they intentionally do not change between
// installs of this fork.
pub const OFFLINE_BLOCK_RULE_NAME: &str = "tinyharness_sandbox_offline_block_outbound";
pub const OFFLINE_BLOCK_INBOUND_RULE_NAME: &str = "tinyharness_sandbox_offline_block_inbound";
pub const OFFLINE_BLOCK_LOOPBACK_TCP_RULE_NAME: &str =
    "tinyharness_sandbox_offline_block_loopback_tcp";
pub const OFFLINE_BLOCK_LOOPBACK_UDP_RULE_NAME: &str =
    "tinyharness_sandbox_offline_block_loopback_udp";
pub const OFFLINE_PROXY_ALLOW_RULE_NAME: &str = "tinyharness_sandbox_offline_allow_loopback_proxy";

// Friendly text shown in the firewall UI.
pub const OFFLINE_BLOCK_RULE_FRIENDLY: &str =
    "TinyHarness Sandbox Offline - Block Non-Loopback Outbound";
pub const OFFLINE_BLOCK_INBOUND_RULE_FRIENDLY: &str =
    "TinyHarness Sandbox Offline - Block Non-Loopback Inbound";
pub const OFFLINE_BLOCK_LOOPBACK_TCP_RULE_FRIENDLY: &str =
    "TinyHarness Sandbox Offline - Block Loopback TCP (Except Proxy)";
pub const OFFLINE_BLOCK_LOOPBACK_UDP_RULE_FRIENDLY: &str =
    "TinyHarness Sandbox Offline - Block Loopback UDP";

// Registry records. Package updates can replace the service key, so the
// installation record is kept outside it.
pub const INSTALLATION_KEY: &str = r"SOFTWARE\TinyHarness\WindowsSandboxService";
pub const CORE_INSTALLATION_KEY: &str =
    r"SOFTWARE\TinyHarness\WindowsSandboxService\RegisteredCore";

// Named pipe used by the machine-wide provisioning service. Distinct from the
// Codex pipe so provisioning requests are never answered by the other install.
pub const SANDBOX_PROVISIONING_PIPE_NAME: &str = r"\\.\pipe\TinyHarness.Sandbox";

// SCM service name matching this fork's identity; packaged builds append the
// package family suffix in `service_identity`.
pub const WINDOWS_SANDBOX_SERVICE_NAME: &str = "TinyHarnessSandboxService";

// Machine- and session-wide mutex names.
pub const SETUP_MUTEX_NAME: &str = r"Global\TinyHarnessSandboxSetup";
pub const READ_ACL_MUTEX_NAME: &str = r"Local\TinyHarnessSandboxReadAcl";

// Private desktop names carry this prefix plus a random hex suffix.
pub const PRIVATE_DESKTOP_PREFIX: &str = "TinyHarnessDesktop-";

// WFP object names.
pub const WFP_SESSION_NAME: &str = "TinyHarness Windows Sandbox WFP";
pub const WFP_PROVIDER_NAME: &str = "TinyHarness Windows Sandbox WFP";
pub const WFP_PROVIDER_DESCRIPTION: &str =
    "Persistent WFP provider for TinyHarness Windows sandbox filters";
pub const WFP_SUBLAYER_NAME: &str = "TinyHarness Windows Sandbox WFP";
pub const WFP_SUBLAYER_DESCRIPTION: &str =
    "Persistent WFP sublayer for TinyHarness Windows sandbox filters";

// WFP identifies persistent providers, sublayers, and filters by stable GUIDs.
// These values are TinyHarness-owned identities; do not regenerate them unless
// we intentionally want to orphan old objects and create a new WFP namespace.
pub const WFP_PROVIDER_KEY: GUID = GUID::from_u128(0xfa06366e_41e5_56a3_8335_10c1246770b1);
pub const WFP_SUBLAYER_KEY: GUID = GUID::from_u128(0xebbd0adf_4e1c_525a_a153_5c91578029fc);

pub const WFP_FILTER_ICMP_CONNECT_V4_KEY: GUID =
    GUID::from_u128(0x76ac377e_60a3_5b7b_9adc_1e078ec3862c);
pub const WFP_FILTER_ICMP_CONNECT_V6_KEY: GUID =
    GUID::from_u128(0x93b6a90a_ac86_5275_b675_208b5f1d7164);
pub const WFP_FILTER_ICMP_ASSIGN_V4_KEY: GUID =
    GUID::from_u128(0x6f3e84f1_d4da_56de_9297_2b81ba738549);
pub const WFP_FILTER_ICMP_ASSIGN_V6_KEY: GUID =
    GUID::from_u128(0xd6ff499d_164d_587b_bff1_2cfcc96c00d9);
pub const WFP_FILTER_DNS_53_V4_KEY: GUID = GUID::from_u128(0x0a180fea_49ca_58f0_a0ed_891ef9e4fb07);
pub const WFP_FILTER_DNS_53_V6_KEY: GUID = GUID::from_u128(0x9a7cff5f_ce3d_57fa_917d_89957324215c);
pub const WFP_FILTER_DNS_853_V4_KEY: GUID = GUID::from_u128(0x09b27c82_2f55_5d02_8df6_da4c6d5f2c5b);
pub const WFP_FILTER_DNS_853_V6_KEY: GUID = GUID::from_u128(0x7a260007_c7fe_53b2_b70e_f309944a7269);
pub const WFP_FILTER_SMB_445_V4_KEY: GUID = GUID::from_u128(0x84968847_da00_55b2_88c4_160ddf012559);
pub const WFP_FILTER_SMB_445_V6_KEY: GUID = GUID::from_u128(0x4493cee6_7887_55b6_b392_d4150e5a8e88);
pub const WFP_FILTER_SMB_139_V4_KEY: GUID = GUID::from_u128(0x6e77328e_bf23_5d72_92f6_ebf1d0ac28f4);
pub const WFP_FILTER_SMB_139_V6_KEY: GUID = GUID::from_u128(0xf409acf4_c99e_527d_afab_a6a52ec54336);
pub const WFP_FILTER_TCP_CONNECT_V4_KEY: GUID =
    GUID::from_u128(0x5a479b6f_81ec_51bd_a2dc_98a1c26f7f10);
pub const WFP_FILTER_TCP_CONNECT_V6_KEY: GUID =
    GUID::from_u128(0xc0aa7448_6b12_5eac_8f34_6723ad6b1975);
pub const WFP_FILTER_UDP_CONNECT_V4_KEY: GUID =
    GUID::from_u128(0x3c9112e8_d0f7_56b3_bf8a_46d701be529c);
pub const WFP_FILTER_UDP_CONNECT_V6_KEY: GUID =
    GUID::from_u128(0x8e2d65a1_4c39_5f07_a6bd_11f824c0e973);
