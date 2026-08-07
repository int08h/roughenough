/// The `VERS` tag contains the list of uint32 Roughtime protocol version
/// numbers a server supports (RFC 5.2.5). Same wire format as the client-side
/// VER tag, so both are the one [`VersionList`](crate::version_list::VersionList)
/// type; only the tag they are carried in differs.
pub type SupportedVersions = crate::version_list::VersionList;
