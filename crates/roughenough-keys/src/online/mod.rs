#[cfg(all(target_os = "linux", feature = "online-linux-krs"))]
pub mod linuxkrs;
#[cfg(feature = "online-ssh-agent")]
pub mod sshagent;

#[cfg(feature = "online-pkcs11")]
pub mod pkcs11;

pub mod memory;
pub mod onlinekey;
mod test_util;

pub use onlinekey::OnlineKey;
