//! Representing lists of Roughtime servers

use roughenough_common::crypto::random_bytes;
use serde::Deserialize;

/// Represents a Roughtime server list
#[derive(Debug, Clone, Deserialize)]
pub struct ServerList {
    /// List of Roughtime servers
    servers: Vec<Server>,

    /// Optional list of URLs where updated versions of the list may be acquired
    sources: Option<Vec<String>>,

    /// Optional URL where malfeasance reports can be sent
    #[serde(rename = "reports")]
    reporting_url: Option<String>,
}

/// Represents a single Roughtime server
#[derive(Debug, Clone, Deserialize)]
pub struct Server {
    /// Server name suitable for display to a user
    name: String,

    /// Highest Roughtime version number supported by the server
    version: ServerVersion,

    /// Signature scheme used by the server (e.g., "ed25519")
    #[serde(rename = "publicKeyType")]
    public_key_type: String,

    /// Base64-encoded long-term public key of the server
    #[serde(rename = "publicKey")]
    public_key: String,

    /// List of network addresses for the server
    addresses: Vec<Address>,
}

/// The `version` of a server list entry. RFC 8.3 specifies an integer. Lists
/// written before RFC 10049 use strings such as "IETF-Roughtime"; those are
/// accepted and kept as-is. Neither form is interpreted.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(untagged)]
pub enum ServerVersion {
    Integer(u32),
    Legacy(String),
}

/// Represents a network address for a Roughtime server
#[derive(Debug, Clone, Deserialize)]
pub struct Address {
    /// Transport protocol ("tcp" or "udp")
    protocol: Protocol,

    /// Parsed from a "host:port" string
    address: HostPort,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(try_from = "String")]
struct HostPort {
    host: String,
    port: u16,
}

/// Transport protocol
#[derive(Debug, Clone, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

/// Validation errors for json server lists
#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("field '{field}' is empty")]
    EmptyField { field: String },

    #[error("Invalid address: expected 'host:port', got '{address}'")]
    InvalidAddress { address: String },

    #[error("Invalid URL: {reason}")]
    InvalidUrl { reason: String },

    #[error("JSON error: {0}")]
    InvalidJson(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Configuration error: {0}")]
    ConfigError(String),
}

impl ServerList {
    fn validate(&self) -> Result<(), Error> {
        if self.servers.is_empty() {
            return Err(Error::EmptyField {
                field: "server list".to_string(),
            });
        }

        for server in self.servers.iter() {
            server.validate()?;
        }

        if let Some(sources) = &self.sources {
            for url in sources.iter() {
                if !url.starts_with("https://") {
                    return Err(Error::InvalidUrl {
                        reason: format!("Source URL must use HTTPS scheme: {url}"),
                    });
                }
            }
        }

        if let Some(reports) = &self.reporting_url
            && !reports.starts_with("https://")
        {
            return Err(Error::InvalidUrl {
                reason: format!("Reports URL must use HTTPS scheme: {reports}"),
            });
        }

        Ok(())
    }

    /// Parses a server list from JSON and validates it
    pub fn from_json(json: &str) -> Result<Self, Error> {
        let server_list: ServerList = serde_json::from_str(json)?;
        server_list.validate()?;
        Ok(server_list)
    }

    /// Loads a server list from a file
    pub fn from_file(file_name: &str) -> Result<Self, Error> {
        let json = std::fs::read_to_string(file_name)?;
        Self::from_json(&json)
    }

    /// Randomly selects n servers from the list
    pub fn choose_random(&self, n: usize) -> Result<Vec<&Server>, Error> {
        if n > self.servers.len() {
            return Err(Error::ConfigError(format!(
                "requested {} servers but only {} available",
                n,
                self.servers.len()
            )));
        }

        let mut servers: Vec<&Server> = self.servers.iter().collect();
        secure_shuffle(&mut servers);
        servers.truncate(n);
        Ok(servers)
    }

    pub fn servers(&self) -> &[Server] {
        &self.servers
    }

    /// Returns the malfeasance reports URL if configured
    pub fn reporting_url(&self) -> Option<&str> {
        self.reporting_url.as_deref()
    }
}

impl Server {
    fn validate(&self) -> Result<(), Error> {
        if self.name.is_empty() {
            return Err(Error::EmptyField {
                field: "name".to_string(),
            });
        }

        if self.version == ServerVersion::Legacy(String::new()) {
            return Err(Error::EmptyField {
                field: "version".to_string(),
            });
        }

        if self.public_key_type.is_empty() {
            return Err(Error::EmptyField {
                field: "publicKeyType".to_string(),
            });
        }

        if self.public_key.is_empty() {
            return Err(Error::EmptyField {
                field: "publicKey".to_string(),
            });
        }

        if self.addresses.is_empty() {
            return Err(Error::EmptyField {
                field: format!("{}.addresses", self.name.clone()),
            });
        }

        Ok(())
    }

    pub fn first_udp_address(&self) -> Option<&Address> {
        self.addresses.iter().find(|a| a.protocol == Protocol::Udp)
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

impl Address {
    pub fn host(&self) -> &str {
        &self.address.host
    }

    pub fn port(&self) -> u16 {
        self.address.port
    }
}

impl TryFrom<String> for HostPort {
    type Error = Error;

    // Splitting on the last ':' also accepts an unbracketed IPv6 literal followed by a port.
    // Brackets are stripped rather than parsing a SocketAddr so an IPv6 zone ID ("%eth0")
    // reaches the resolver intact.
    fn try_from(address: String) -> Result<Self, Error> {
        let parsed = address.rsplit_once(':').and_then(|(host, port)| {
            let host = host
                .strip_prefix('[')
                .and_then(|h| h.strip_suffix(']'))
                .unwrap_or(host);
            match (host.is_empty(), port.parse()) {
                (false, Ok(port)) => Some(HostPort {
                    host: host.to_string(),
                    port,
                }),
                _ => None,
            }
        });
        parsed.ok_or(Error::InvalidAddress { address })
    }
}

/// Shuffle a slice in place (Fisher-Yates) using cryptographically secure randomness
fn secure_shuffle<T>(slice: &mut [T]) {
    for i in (1..slice.len()).rev() {
        let j = random_index(i + 1);
        slice.swap(i, j);
    }
}

/// Uniform random index in `[0, bound)`; rejection sampling avoids modulo bias
fn random_index(bound: usize) -> usize {
    debug_assert!(bound > 0 && bound <= u32::MAX as usize);
    let bound = bound as u32;
    let zone = u32::MAX - (u32::MAX % bound);
    loop {
        let r = u32::from_le_bytes(random_bytes::<4>());
        if r < zone {
            return (r % bound) as usize;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// JSON for a one-server list whose `addresses` array holds `addresses`
    fn list_with_addresses(addresses: &str) -> String {
        format!(
            r#"{{
                "servers": [{{
                    "name": "Server",
                    "version": 1,
                    "publicKeyType": "ed25519",
                    "publicKey": "key==",
                    "addresses": [{addresses}]
                }}]
            }}"#
        )
    }

    fn udp(address: &str) -> String {
        format!(r#"{{"protocol": "udp", "address": "{address}"}}"#)
    }

    fn parse_address(address: &str) -> Result<Address, Error> {
        ServerList::from_json(&list_with_addresses(&udp(address)))
            .map(|list| list.servers[0].addresses[0].clone())
    }

    fn assert_invalid_address(result: Result<impl std::fmt::Debug, Error>, address: &str) {
        match result {
            Err(Error::InvalidJson(e)) => {
                let msg = e.to_string();
                assert!(msg.contains("Invalid address"), "{msg}");
                assert!(msg.contains(&format!("'{address}'")), "{msg}");
            }
            other => panic!("expected an invalid address error, got {other:?}"),
        }
    }

    #[test]
    fn test_server_list_creation() {
        let json = r#"{
            "servers": [
                {
                    "name": "Example Server",
                    "version": 1,
                    "publicKeyType": "ed25519",
                    "publicKey": "base64encodedkey==",
                    "addresses": [{"protocol": "udp", "address": "roughtime.example.com:2002"}]
                },
                {
                    "name": "Other Server",
                    "version": 1,
                    "publicKeyType": "ed25519",
                    "publicKey": "anotherkeyhere==",
                    "addresses": [{"protocol": "tcp", "address": "other.example.com:2003"}]
                }
            ],
            "reports": "https://example.com/reports"
        }"#;

        let server_list = ServerList::from_json(json).unwrap();
        assert_eq!(server_list.servers().len(), 2);
        assert_eq!(server_list.servers()[0].name(), "Example Server");
        assert_eq!(server_list.servers()[0].public_key(), "base64encodedkey==");
        assert_eq!(server_list.servers()[1].public_key_type, "ed25519");
        assert_eq!(
            server_list.reporting_url(),
            Some("https://example.com/reports")
        );
    }

    #[test]
    fn test_empty_server_list_fails() {
        match ServerList::from_json(r#"{"servers": []}"#) {
            Err(Error::EmptyField { field }) => assert_eq!(field, "server list"),
            Err(e) => panic!("expected Error::EmptyField, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn test_address_parsing() {
        let address = parse_address("example.com:2002").unwrap();
        assert_eq!(address.host(), "example.com");
        assert_eq!(address.port(), 2002);
    }

    #[test]
    fn test_invalid_addresses() {
        assert_invalid_address(parse_address("invalid_address"), "invalid_address");
        assert_invalid_address(
            parse_address("example.com:not_a_port"),
            "example.com:not_a_port",
        );
        assert_invalid_address(parse_address("example.com:65536"), "example.com:65536");
        assert_invalid_address(parse_address(":2002"), ":2002");
        assert_invalid_address(parse_address("[]:2002"), "[]:2002");
    }

    #[test]
    fn test_ipv6_address_parses() {
        // A bracketed IPv6 literal must not poison the whole list
        let address = parse_address("[2001:db8::1]:2003").unwrap();
        assert_eq!(address.host(), "2001:db8::1");
        assert_eq!(address.port(), 2003);
    }

    #[test]
    fn unbracketed_ipv6_splits_on_last_colon() {
        let address = parse_address("2001:db8::1:2003").unwrap();
        assert_eq!(address.host(), "2001:db8::1");
        assert_eq!(address.port(), 2003);
    }

    #[test]
    fn ipv6_zone_id_is_kept() {
        let address = parse_address("[fe80::1%eth0]:2003").unwrap();
        assert_eq!(address.host(), "fe80::1%eth0");
        assert_eq!(address.port(), 2003);
    }

    #[test]
    fn test_ipv4_and_hostname_addresses_still_parse() {
        let v4 = parse_address("192.0.2.7:2003").unwrap();
        assert_eq!(v4.host(), "192.0.2.7");
        assert_eq!(v4.port(), 2003);

        let hostname = parse_address("roughtime.example.com:2002").unwrap();
        assert_eq!(hostname.host(), "roughtime.example.com");
        assert_eq!(hostname.port(), 2002);
    }

    #[test]
    fn test_tcp_only_server_has_no_udp_address() {
        let json = list_with_addresses(r#"{"protocol": "tcp", "address": "example.com:2003"}"#);
        let server_list = ServerList::from_json(&json).unwrap();

        assert!(server_list.servers()[0].first_udp_address().is_none());
    }

    #[test]
    fn test_mixed_addresses_select_udp() {
        let addresses = format!(
            r#"{{"protocol": "tcp", "address": "example.com:2003"}}, {}"#,
            udp("example.com:2004")
        );
        let server_list = ServerList::from_json(&list_with_addresses(&addresses)).unwrap();

        let selected = server_list.servers()[0].first_udp_address().unwrap();
        assert_eq!(selected.protocol, Protocol::Udp);
        assert_eq!(selected.port(), 2004);
    }

    #[test]
    fn integer_and_legacy_versions_parse() {
        let json = r#"{
            "servers": [
                {
                    "name": "RFC",
                    "version": 1,
                    "publicKeyType": "ed25519",
                    "publicKey": "key==",
                    "addresses": [{"protocol": "udp", "address": "example.com:5319"}]
                },
                {
                    "name": "Legacy",
                    "version": "IETF-Roughtime",
                    "publicKeyType": "ed25519",
                    "publicKey": "key==",
                    "addresses": [{"protocol": "udp", "address": "example.com:2002"}]
                }
            ]
        }"#;

        let server_list = ServerList::from_json(json).unwrap();
        assert_eq!(server_list.servers[0].version, ServerVersion::Integer(1));
        assert_eq!(
            server_list.servers[1].version,
            ServerVersion::Legacy("IETF-Roughtime".to_string())
        );
    }

    #[test]
    fn empty_legacy_version_is_rejected() {
        let json = r#"{
            "servers": [{
                "name": "Server",
                "version": "",
                "publicKeyType": "ed25519",
                "publicKey": "key==",
                "addresses": [{"protocol": "udp", "address": "example.com:5319"}]
            }]
        }"#;
        match ServerList::from_json(json) {
            Err(Error::EmptyField { field }) => assert_eq!(field, "version"),
            Err(e) => panic!("expected Error::EmptyField, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn can_read_cloudflare_list() {
        let json = include_str!("../testdata/serverlist-cloudflare.json");
        let server_list: ServerList = ServerList::from_json(json).unwrap();
        assert_eq!(server_list.servers.len(), 4);
    }

    #[test]
    fn test_invalid_json_fails() {
        // Empty server list
        let json = r#"{"servers": []}"#;
        match ServerList::from_json(json) {
            Err(Error::EmptyField { field }) => assert_eq!(field, "server list"),
            Err(e) => panic!("expected Error::EmptyField, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }

        // Empty server name
        let json = r#"{
            "servers": [{
                "name": "",
                "version": 1,
                "publicKeyType": "ed25519",
                "publicKey": "key==",
                "addresses": [{"protocol": "udp", "address": "example.com:2002"}]
            }]
        }"#;
        match ServerList::from_json(json) {
            Err(Error::EmptyField { field }) => assert_eq!(field, "name"),
            Err(e) => panic!("expected Error::EmptyField, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }

        // Invalid address format
        assert_invalid_address(
            ServerList::from_json(&list_with_addresses(&udp("no_port"))),
            "no_port",
        );

        // Non-HTTPS source URL
        let json = r#"{
            "servers": [{
                "name": "Server",
                "version": 1,
                "publicKeyType": "ed25519",
                "publicKey": "key==",
                "addresses": [{"protocol": "udp", "address": "example.com:2002"}]
            }],
            "sources": ["http://example.com"]
        }"#;
        match ServerList::from_json(json) {
            Err(Error::InvalidUrl { reason }) => assert!(reason.contains("HTTPS scheme")),
            Err(e) => panic!("expected Error::InvalidUrl, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn test_server_validation() {
        // Empty name
        let json = r#"{
            "servers": [{
                "name": "",
                "version": 1,
                "publicKeyType": "ed25519",
                "publicKey": "key==",
                "addresses": [{"protocol": "udp", "address": "example.com:2002"}]
            }]
        }"#;
        match ServerList::from_json(json) {
            Err(Error::EmptyField { field }) => assert_eq!(field, "name"),
            Err(e) => panic!("expected Error::EmptyField, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }

        // Empty addresses
        match ServerList::from_json(&list_with_addresses("")) {
            Err(Error::EmptyField { field }) => assert!(field.contains("addresses")),
            Err(e) => panic!("expected Error::EmptyField, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn test_sources_validation() {
        let with_source = |url: &str| {
            format!(
                r#"{{
                    "servers": [{{
                        "name": "Server",
                        "version": 1,
                        "publicKeyType": "ed25519",
                        "publicKey": "key==",
                        "addresses": [{{"protocol": "udp", "address": "example.com:2002"}}]
                    }}],
                    "sources": ["{url}"]
                }}"#
            )
        };

        let server_list =
            ServerList::from_json(&with_source("https://example.com/list.json")).unwrap();
        assert_eq!(
            server_list.sources,
            Some(vec!["https://example.com/list.json".to_string()])
        );

        match ServerList::from_json(&with_source("http://example.com/list.json")) {
            Err(Error::InvalidUrl { reason }) => assert!(reason.contains("HTTPS scheme")),
            Err(e) => panic!("expected Error::InvalidUrl, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn choose_random_returns_n_distinct_servers() {
        let json = include_str!("../testdata/serverlist-cloudflare.json");
        let server_list = ServerList::from_json(json).unwrap();

        for n in 0..=server_list.servers().len() {
            let chosen = server_list.choose_random(n).unwrap();
            assert_eq!(chosen.len(), n);

            let mut names: Vec<&str> = chosen.iter().map(|s| s.name()).collect();
            names.sort_unstable();
            names.dedup();
            assert_eq!(names.len(), n, "duplicate server chosen");
        }

        assert!(matches!(
            server_list.choose_random(server_list.servers().len() + 1),
            Err(Error::ConfigError(_))
        ));
    }

    #[test]
    fn secure_shuffle_is_a_permutation() {
        for len in [0, 1, 2, 3, 17, 100] {
            let original: Vec<usize> = (0..len).collect();
            for _ in 0..10 {
                let mut shuffled = original.clone();
                secure_shuffle(&mut shuffled);
                shuffled.sort_unstable();
                assert_eq!(shuffled, original);
            }
        }
    }
}
