mod aws_lc_ed25519;
#[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
pub mod linuxkrs;
#[cfg(feature = "online-ssh-agent")]
pub mod sshagent;

#[cfg(feature = "online-pkcs11")]
pub mod pkcs11;

pub mod memory;
pub mod onlinekey;
// Only the device-backed backends' tests log, so gate on the same cfgs to avoid dead code
#[cfg(all(
    test,
    any(
        all(target_os = "linux", feature = "online-linux-krs"),
        feature = "online-ssh-agent",
        feature = "online-pkcs11"
    )
))]
mod test_util;

pub use onlinekey::OnlineKey;
