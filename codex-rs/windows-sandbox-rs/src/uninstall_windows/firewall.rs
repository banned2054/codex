//! Removes known sandbox firewall rules while preserving unrelated rules.

use anyhow::Context;
use anyhow::Result;
use anyhow::anyhow;
use windows::Win32::NetworkManagement::WindowsFirewall::INetFwPolicy2;
use windows::Win32::NetworkManagement::WindowsFirewall::NetFwPolicy2;
use windows::Win32::System::Com::CLSCTX_INPROC_SERVER;
use windows::Win32::System::Com::CoCreateInstance;
use windows::core::BSTR;

pub(super) fn cleanup_firewall_rules() -> Result<()> {
    let policy: INetFwPolicy2 = unsafe {
        CoCreateInstance(&NetFwPolicy2, /*punkouter*/ None, CLSCTX_INPROC_SERVER)
            .context("access firewall policy for sandbox uninstall")?
    };
    let rules = unsafe { policy.Rules() }.context("access sandbox firewall rules")?;
    let mut errors = Vec::new();
    for name in [
        crate::branding::OFFLINE_BLOCK_RULE_NAME,
        crate::branding::OFFLINE_BLOCK_INBOUND_RULE_NAME,
        crate::branding::OFFLINE_BLOCK_LOOPBACK_TCP_RULE_NAME,
        crate::branding::OFFLINE_BLOCK_LOOPBACK_UDP_RULE_NAME,
        crate::branding::OFFLINE_PROXY_ALLOW_RULE_NAME,
    ] {
        for scoped_name in [name.to_owned(), format!("{name}_tcp_loopback")] {
            if let Err(error) = unsafe { rules.Remove(&BSTR::from(scoped_name.as_str())) } {
                errors.push(format!(
                    "remove sandbox firewall rule {scoped_name}: {error}"
                ));
            }
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(anyhow!(errors.join("; ")))
    }
}
