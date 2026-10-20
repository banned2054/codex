use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::{
    FWP_BYTE_ARRAY16, FWP_BYTE_ARRAY16_TYPE, FWP_MATCH_NOT_EQUAL, FWP_MATCH_RANGE, FWP_RANGE_TYPE,
    FWP_RANGE0, FWP_UINT32, FWPM_CONDITION_IP_REMOTE_ADDRESS,
};
mod filter_specs;

use crate::to_wide;
use anyhow::Result;
use std::ffi::OsStr;
use std::mem::zeroed;
use std::ptr::null;
use std::ptr::null_mut;
use windows_sys::Win32::Foundation::FWP_E_ALREADY_EXISTS;
use windows_sys::Win32::Foundation::FWP_E_FILTER_NOT_FOUND;
use windows_sys::Win32::Foundation::FWP_E_NOT_FOUND;
use windows_sys::Win32::Foundation::FWP_E_PROVIDER_NOT_FOUND;
use windows_sys::Win32::Foundation::FWP_E_SUBLAYER_NOT_FOUND;
use windows_sys::Win32::Foundation::HANDLE;
use windows_sys::Win32::Foundation::HLOCAL;
use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTION_BLOCK;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_ACTRL_MATCH_FILTER;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_BYTE_BLOB;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_CONDITION_VALUE0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_EMPTY;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_MATCH_EQUAL;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_SECURITY_DESCRIPTOR_TYPE;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT8;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_UINT16;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_ACTION0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_ALE_USER_ID;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_PROTOCOL;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_CONDITION_IP_REMOTE_PORT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_DISPLAY_DATA0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_CONDITION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_FILTER0_0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_PROVIDER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SESSION0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER_FLAG_PERSISTENT;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_SUBLAYER0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineClose0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmEngineOpen0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmFilterDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmProviderAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmProviderDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerAdd0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmSubLayerDeleteByKey0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionAbort0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionBegin0;
use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FwpmTransactionCommit0;
use windows_sys::Win32::Security::Authorization::BuildExplicitAccessWithNameW;
use windows_sys::Win32::Security::Authorization::BuildSecurityDescriptorW;
use windows_sys::Win32::Security::Authorization::EXPLICIT_ACCESS_W;
use windows_sys::Win32::Security::Authorization::GRANT_ACCESS;
use windows_sys::Win32::Security::PSECURITY_DESCRIPTOR;
use windows_sys::Win32::System::Rpc::RPC_C_AUTHN_DEFAULT;
use windows_sys::Win32::System::Threading::INFINITE;
use windows_sys::core::GUID;

use filter_specs::ConditionSpec;
#[cfg(test)]
use filter_specs::FILTER_SPECS;
use filter_specs::FilterSpec;

// WFP object names and keys are TinyHarness-owned identities defined in
// branding; see that module for why they must not collide with Codex's.
const SESSION_NAME: &str = crate::branding::WFP_SESSION_NAME;
const PROVIDER_NAME: &str = crate::branding::WFP_PROVIDER_NAME;
const PROVIDER_DESCRIPTION: &str = crate::branding::WFP_PROVIDER_DESCRIPTION;
const SUBLAYER_NAME: &str = crate::branding::WFP_SUBLAYER_NAME;
const SUBLAYER_DESCRIPTION: &str = crate::branding::WFP_SUBLAYER_DESCRIPTION;
const PROVIDER_KEY: GUID = crate::branding::WFP_PROVIDER_KEY;
const SUBLAYER_KEY: GUID = crate::branding::WFP_SUBLAYER_KEY;

/// Installs the persistent Codex WFP filters for `account`.
///
/// This is intended to run from the already-elevated setup helper. Callers
/// may continue ordinary setup after an error, but must restore these filters
/// before re-enabling accounts left disabled by interrupted cleanup.
pub fn install_wfp_filters_for_account(account: &str) -> Result<usize> {
    install_wfp_filters_for_account_with_tcp_loopback(account, false)
}

pub fn install_wfp_filters_for_account_with_tcp_loopback(
    account: &str,
    allow_tcp_loopback: bool,
) -> Result<usize> {
    if allow_tcp_loopback {
        anyhow::ensure!(
            account == crate::branding::TCP_LOOPBACK_OFFLINE_USERNAME,
            "TCP loopback requires its separate sandbox account"
        );
    }
    let engine = Engine::open(INFINITE)?;
    let mut transaction = engine.begin_transaction()?;
    ensure_provider(engine.handle)?;
    ensure_sublayer(engine.handle)?;

    let user_condition = UserMatchCondition::for_account(account)?;
    let mut installed_filter_count = 0;
    for spec in filter_specs::specs_for_mode(allow_tcp_loopback) {
        delete_filter_if_present(engine.handle, &spec.key)?;
        add_filter(engine.handle, &spec, &user_condition)?;
        installed_filter_count += 1;
    }

    transaction.commit()?;
    Ok(installed_filter_count)
}

pub(crate) fn remove_wfp_filters() -> Result<()> {
    // Leave time for other cleanup if a WFP policy writer holds the transaction lock.
    let engine = Engine::open(/*transaction_wait_timeout_ms*/ 1_000)?;
    let mut transaction = engine.begin_transaction()?;
    for spec in filter_specs::specs_for_mode(false)
        .into_iter()
        .chain(filter_specs::specs_for_mode(true))
    {
        delete_filter_if_present(engine.handle, &spec.key)?;
    }
    for (result, operation, missing) in [
        (
            unsafe { FwpmSubLayerDeleteByKey0(engine.handle, &SUBLAYER_KEY) },
            "FwpmSubLayerDeleteByKey0",
            FWP_E_SUBLAYER_NOT_FOUND as u32,
        ),
        (
            unsafe { FwpmProviderDeleteByKey0(engine.handle, &PROVIDER_KEY) },
            "FwpmProviderDeleteByKey0",
            FWP_E_PROVIDER_NOT_FOUND as u32,
        ),
    ] {
        ensure_success_or(result, operation, &[missing, FWP_E_NOT_FOUND as u32])?;
    }
    transaction.commit()
}

/// Owns an open WFP engine handle and closes it on drop.
struct Engine {
    handle: HANDLE,
}

impl Engine {
    fn open(transaction_wait_timeout_ms: u32) -> Result<Self> {
        let session_name = to_wide(OsStr::new(SESSION_NAME));
        let mut session: FWPM_SESSION0 = unsafe { zeroed() };
        session.displayData = FWPM_DISPLAY_DATA0 {
            name: session_name.as_ptr() as *mut _,
            description: null_mut(),
        };
        session.txnWaitTimeoutInMSec = transaction_wait_timeout_ms;

        let mut handle = HANDLE::default();
        let result = unsafe {
            FwpmEngineOpen0(
                null(),
                RPC_C_AUTHN_DEFAULT as u32,
                null(),
                &session,
                &mut handle,
            )
        };
        ensure_success(result, "FwpmEngineOpen0")?;
        Ok(Self { handle })
    }

    fn begin_transaction(&self) -> Result<Transaction<'_>> {
        let result = unsafe { FwpmTransactionBegin0(self.handle, 0) };
        ensure_success(result, "FwpmTransactionBegin0")?;
        Ok(Transaction {
            engine: self,
            committed: false,
        })
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        unsafe {
            FwpmEngineClose0(self.handle);
        }
    }
}

/// Aborts an open WFP transaction unless it was explicitly committed.
struct Transaction<'a> {
    engine: &'a Engine,
    committed: bool,
}

impl Transaction<'_> {
    fn commit(&mut self) -> Result<()> {
        let result = unsafe { FwpmTransactionCommit0(self.engine.handle) };
        ensure_success(result, "FwpmTransactionCommit0")?;
        self.committed = true;
        Ok(())
    }
}

impl Drop for Transaction<'_> {
    fn drop(&mut self) {
        if !self.committed {
            unsafe {
                FwpmTransactionAbort0(self.engine.handle);
            }
        }
    }
}

/// Builds the ALE_USER_ID condition blob that scopes filters to one account.
struct UserMatchCondition {
    security_descriptor: PSECURITY_DESCRIPTOR,
    blob: FWP_BYTE_BLOB,
}

impl UserMatchCondition {
    fn for_account(account: &str) -> Result<Self> {
        let account_w = to_wide(OsStr::new(account));
        let mut access: EXPLICIT_ACCESS_W = unsafe { zeroed() };
        unsafe {
            BuildExplicitAccessWithNameW(
                &mut access,
                account_w.as_ptr(),
                FWP_ACTRL_MATCH_FILTER,
                GRANT_ACCESS,
                0,
            );
        }

        let mut security_descriptor: PSECURITY_DESCRIPTOR = null_mut();
        let mut security_descriptor_len = 0;
        let result = unsafe {
            BuildSecurityDescriptorW(
                null(),
                null(),
                1,
                &access,
                0,
                null(),
                null_mut(),
                &mut security_descriptor_len,
                &mut security_descriptor,
            )
        };
        ensure_success(result, "BuildSecurityDescriptorW")?;

        Ok(Self {
            security_descriptor,
            blob: FWP_BYTE_BLOB {
                size: security_descriptor_len,
                data: security_descriptor as *mut u8,
            },
        })
    }
}

impl Drop for UserMatchCondition {
    fn drop(&mut self) {
        if !self.security_descriptor.is_null() {
            unsafe {
                LocalFree(self.security_descriptor as HLOCAL);
            }
        }
    }
}

/// Ensures the persistent Codex WFP provider exists.
fn ensure_provider(engine: HANDLE) -> Result<()> {
    let provider_name = to_wide(OsStr::new(PROVIDER_NAME));
    let provider_description = to_wide(OsStr::new(PROVIDER_DESCRIPTION));
    let provider = FWPM_PROVIDER0 {
        providerKey: PROVIDER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: provider_name.as_ptr() as *mut _,
            description: provider_description.as_ptr() as *mut _,
        },
        flags: FWPM_PROVIDER_FLAG_PERSISTENT,
        providerData: empty_blob(),
        serviceName: null_mut(),
    };

    let result = unsafe { FwpmProviderAdd0(engine, &provider, null_mut()) };
    ensure_success_or(result, "FwpmProviderAdd0", &[FWP_E_ALREADY_EXISTS as u32])
}

/// Ensures the persistent Codex sublayer exists under the Codex provider.
fn ensure_sublayer(engine: HANDLE) -> Result<()> {
    let sublayer_name = to_wide(OsStr::new(SUBLAYER_NAME));
    let sublayer_description = to_wide(OsStr::new(SUBLAYER_DESCRIPTION));
    let provider_key = PROVIDER_KEY;
    let sublayer = FWPM_SUBLAYER0 {
        subLayerKey: SUBLAYER_KEY,
        displayData: FWPM_DISPLAY_DATA0 {
            name: sublayer_name.as_ptr() as *mut _,
            description: sublayer_description.as_ptr() as *mut _,
        },
        flags: FWPM_SUBLAYER_FLAG_PERSISTENT,
        providerKey: &provider_key as *const _ as *mut _,
        providerData: empty_blob(),
        weight: 0x8000,
    };

    let result = unsafe { FwpmSubLayerAdd0(engine, &sublayer, null_mut()) };
    ensure_success_or(result, "FwpmSubLayerAdd0", &[FWP_E_ALREADY_EXISTS as u32])
}

/// Adds one blocking WFP filter from the static filter spec list.
fn add_filter(
    engine: HANDLE,
    spec: &FilterSpec,
    user_condition: &UserMatchCondition,
) -> Result<()> {
    let filter_name = to_wide(OsStr::new(spec.name));
    let filter_description = to_wide(OsStr::new(spec.description));
    let addresses = AddressConditions::new();
    let mut filter_conditions = build_conditions(spec.conditions, user_condition, &addresses);
    let provider_key = PROVIDER_KEY;
    let filter = FWPM_FILTER0 {
        filterKey: spec.key,
        displayData: FWPM_DISPLAY_DATA0 {
            name: filter_name.as_ptr() as *mut _,
            description: filter_description.as_ptr() as *mut _,
        },
        flags: FWPM_FILTER_FLAG_PERSISTENT,
        providerKey: &provider_key as *const _ as *mut _,
        providerData: empty_blob(),
        layerKey: spec.layer_key,
        subLayerKey: SUBLAYER_KEY,
        weight: empty_value(),
        numFilterConditions: filter_conditions.len() as u32,
        filterCondition: filter_conditions.as_mut_ptr(),
        action: FWPM_ACTION0 {
            r#type: FWP_ACTION_BLOCK,
            Anonymous: FWPM_ACTION0_0 {
                filterType: zero_guid(),
            },
        },
        Anonymous: FWPM_FILTER0_0 { rawContext: 0 },
        reserved: null_mut(),
        filterId: 0,
        effectiveWeight: empty_value(),
    };

    let mut filter_id = 0_u64;
    let result = unsafe { FwpmFilterAdd0(engine, &filter, null_mut(), &mut filter_id) };
    ensure_success(result, &format!("FwpmFilterAdd0({})", spec.name))
}

/// Converts our compact condition specs into WFP filter conditions.
fn build_conditions(
    specs: &[ConditionSpec],
    user_condition: &UserMatchCondition,
    addresses: &AddressConditions,
) -> Vec<FWPM_FILTER_CONDITION0> {
    specs
        .iter()
        .map(|spec| match spec {
            ConditionSpec::NonLoopbackV4Low | ConditionSpec::NonLoopbackV4High => {
                FWPM_FILTER_CONDITION0 {
                    fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                    matchType: FWP_MATCH_RANGE,
                    conditionValue: FWP_CONDITION_VALUE0 {
                        r#type: FWP_RANGE_TYPE,
                        Anonymous: FWP_CONDITION_VALUE0_0 {
                            rangeValue: if matches!(spec, ConditionSpec::NonLoopbackV4Low) {
                                &addresses.v4_low as *const _ as *mut _
                            } else {
                                &addresses.v4_high as *const _ as *mut _
                            },
                        },
                    },
                }
            }
            ConditionSpec::NonLoopbackV6 => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_ADDRESS,
                matchType: FWP_MATCH_NOT_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_BYTE_ARRAY16_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        byteArray16: &addresses.v6_loopback as *const _ as *mut _,
                    },
                },
            },
            ConditionSpec::User => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_ALE_USER_ID,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_SECURITY_DESCRIPTOR_TYPE,
                    Anonymous: FWP_CONDITION_VALUE0_0 {
                        sd: &user_condition.blob as *const _ as *mut _,
                    },
                },
            },
            ConditionSpec::Protocol(protocol) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_PROTOCOL,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT8,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint8: *protocol },
                },
            },
            ConditionSpec::RemotePort(port) => FWPM_FILTER_CONDITION0 {
                fieldKey: FWPM_CONDITION_IP_REMOTE_PORT,
                matchType: FWP_MATCH_EQUAL,
                conditionValue: FWP_CONDITION_VALUE0 {
                    r#type: FWP_UINT16,
                    Anonymous: FWP_CONDITION_VALUE0_0 { uint16: *port },
                },
            },
        })
        .collect()
}

/// Deletes an old copy of a filter before re-adding it.
fn delete_filter_if_present(engine: HANDLE, key: &GUID) -> Result<()> {
    let result = unsafe { FwpmFilterDeleteByKey0(engine, key) };
    ensure_success_or(
        result,
        "FwpmFilterDeleteByKey0",
        &[FWP_E_FILTER_NOT_FOUND as u32, FWP_E_NOT_FOUND as u32],
    )
}

fn ensure_success(result: u32, operation: &str) -> Result<()> {
    ensure_success_or(result, operation, &[])
}

fn ensure_success_or(result: u32, operation: &str, allowed: &[u32]) -> Result<()> {
    if result == 0 || allowed.contains(&result) {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "{operation} failed: {}",
            format_error_code(result)
        ))
    }
}

fn format_error_code(result: u32) -> String {
    format!("0x{result:08X}")
}

fn empty_blob() -> FWP_BYTE_BLOB {
    FWP_BYTE_BLOB {
        size: 0,
        data: null_mut(),
    }
}

fn empty_value() -> FWP_VALUE0 {
    FWP_VALUE0 {
        r#type: FWP_EMPTY,
        Anonymous: unsafe { zeroed() },
    }
}

fn zero_guid() -> GUID {
    GUID::from_u128(0)
}

#[cfg(test)]
mod tests {
    use super::FILTER_SPECS;
    use super::filter_specs::ConditionSpec;
    use pretty_assertions::assert_eq;
    use std::collections::BTreeSet;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V4;
    use windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWPM_LAYER_ALE_AUTH_CONNECT_V6;
    use windows_sys::Win32::Networking::WinSock::IPPROTO_TCP;
    use windows_sys::Win32::Networking::WinSock::IPPROTO_UDP;
    use windows_sys::core::GUID;

    fn guid_tuple(guid: &GUID) -> (u32, u16, u16, [u8; 8]) {
        (guid.data1, guid.data2, guid.data3, guid.data4)
    }

    fn assert_transport_filter(name: &str, protocol: u8) {
        let matching = FILTER_SPECS
            .iter()
            .filter(|spec| spec.name.starts_with(name))
            .collect::<Vec<_>>();
        assert_eq!(matching.len(), 2);

        let layers = matching
            .iter()
            .map(|spec| guid_tuple(&spec.layer_key))
            .collect::<BTreeSet<_>>();
        assert_eq!(layers.len(), 2);
        assert!(layers.contains(&guid_tuple(&FWPM_LAYER_ALE_AUTH_CONNECT_V4)));
        assert!(layers.contains(&guid_tuple(&FWPM_LAYER_ALE_AUTH_CONNECT_V6)));

        for spec in matching {
            assert_eq!(spec.conditions.len(), 2);
            assert!(matches!(spec.conditions[0], ConditionSpec::User));
            assert!(matches!(
                spec.conditions[1],
                ConditionSpec::Protocol(value) if value == protocol
            ));
        }
    }

    #[test]
    fn generic_outbound_transport_filters_cover_tcp_udp_and_both_families() {
        assert_transport_filter("tinyharness_wfp_tcp_connect_", IPPROTO_TCP as u8);
        assert_transport_filter("tinyharness_wfp_udp_connect_", IPPROTO_UDP as u8);
    }

    #[test]
    fn filter_keys_are_unique() {
        let keys = FILTER_SPECS
            .iter()
            .map(|spec| {
                (
                    spec.key.data1,
                    spec.key.data2,
                    spec.key.data3,
                    spec.key.data4,
                )
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(keys.len(), FILTER_SPECS.len());
    }

    #[test]
    fn filter_names_are_unique() {
        let names = FILTER_SPECS
            .iter()
            .map(|spec| spec.name)
            .collect::<BTreeSet<_>>();
        assert_eq!(names.len(), FILTER_SPECS.len());
    }
}

// 地址存储活到 FwpmFilterAdd0 返回，避免条件 union 持有临时对象指针。
struct AddressConditions {
    v4_low: FWP_RANGE0,
    v4_high: FWP_RANGE0,
    v6_loopback: FWP_BYTE_ARRAY16,
}

impl AddressConditions {
    fn new() -> Self {
        fn ipv4_range(low: u32, high: u32) -> FWP_RANGE0 {
            FWP_RANGE0 {
                valueLow: FWP_VALUE0 { r#type: FWP_UINT32, Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 { uint32: low } },
                valueHigh: FWP_VALUE0 { r#type: FWP_UINT32, Anonymous: windows_sys::Win32::NetworkManagement::WindowsFilteringPlatform::FWP_VALUE0_0 { uint32: high } },
            }
        }
        Self {
            v4_low: ipv4_range(0, 0x7eff_ffff),
            v4_high: ipv4_range(0x8000_0000, u32::MAX),
            v6_loopback: FWP_BYTE_ARRAY16 {
                byteArray16: std::net::Ipv6Addr::LOCALHOST.octets(),
            },
        }
    }
}

#[cfg(test)]
#[path = "wfp/tcp_loopback_tests.rs"]
mod tcp_loopback_tests;
