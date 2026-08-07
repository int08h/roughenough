/// The `VER` tag contains a list of uint32 Roughtime protocol version numbers
/// offered by a client (RFC 5.1.1). Same wire format as the server-side VERS
/// tag, so both are the one [`VersionList`](crate::version_list::VersionList)
/// type; only the tag they are carried in differs.
pub type RequestedVersions = crate::version_list::VersionList;
