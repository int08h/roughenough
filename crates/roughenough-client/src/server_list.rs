//! Representing lists of Roughtime servers

use serde::{Deserialize, Serialize};

/// Represents a Roughtime server list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerList {
    /// List of Roughtime servers
    servers: Vec<Server>,

    /// Optional list of URLs where updated versions of the list may be acquired
    #[serde(skip_serializing_if = "Option::is_none")]
    sources: Option<Vec<String>>,

    /// Optional URL where malfeasance reports can be sent
    #[serde(rename = "reports", skip_serializing_if = "Option::is_none")]
    reporting_url: Option<String>,
}

/// Represents a single Roughtime server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Server {
    /// Server name suitable for display to a user
    name: String,

    /// Highest Roughtime version number supported by the server
    version: String,

    /// Signature scheme used by the server (e.g., "ed25519")
    #[serde(rename = "publicKeyType")]
    public_key_type: String,

    /// Base64-encoded long-term public key of the server
    #[serde(rename = "publicKey")]
    public_key: String,

    /// List of network addresses for the server
    addresses: Vec<Address>,
}

/// Represents a network address for a Roughtime server
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Address {
    /// Transport protocol ("tcp" or "udp")
    protocol: Protocol,

    /// Host and port in the format "host:port"
    address: String,
}

/// Transport protocol
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    /// Creates a new server list
    pub fn new(
        servers: Vec<Server>,
        sources: Option<Vec<String>>,
        reports: Option<String>,
    ) -> Result<Self, Error> {
        let server_list = Self {
            servers,
            sources,
            reporting_url: reports,
        };
        server_list.validate()?;
        Ok(server_list)
    }

    /// Validates the server list according to RFC requirements
    pub fn validate(&self) -> Result<(), Error> {
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

    /// Serializes the server list to JSON
    pub fn to_json(&self) -> Result<String, Error> {
        serde_json::to_string_pretty(self).map_err(Into::into)
    }

    /// Loads a server list from a file
    pub fn from_file(file_name: &str) -> Result<Self, Error> {
        let json = std::fs::read_to_string(file_name)?;
        Self::from_json(&json)
    }

    /// Randomly selects n servers from the list
    pub fn choose_random(&self, n: usize) -> Result<Vec<Server>, Error> {
        if n > self.servers.len() {
            return Err(Error::ConfigError(format!(
                "requested {} servers but only {} available",
                n,
                self.servers.len()
            )));
        }

        let mut servers = self.servers.clone();
        fastrand::shuffle(&mut servers);
        Ok(servers[..n].to_vec())
    }

    pub fn servers(&self) -> &[Server] {
        &self.servers
    }

    /// Returns the malfeasance reports URL if configured
    pub fn reporting_url(&self) -> Option<&str> {
        self.reporting_url.as_deref()
    }

    /// Adds a server to the list
    pub fn add_server(&mut self, server: Server) {
        self.servers.push(server);
    }
}

impl Server {
    pub fn new(
        name: String,
        version: String,
        public_key_type: String,
        public_key: String,
        addresses: Vec<Address>,
    ) -> Result<Self, Error> {
        let server = Self {
            name,
            version,
            public_key_type,
            public_key,
            addresses,
        };
        server.validate()?;
        Ok(server)
    }

    /// Validates the server entry
    pub fn validate(&self) -> Result<(), Error> {
        if self.name.is_empty() {
            return Err(Error::EmptyField {
                field: "name".to_string(),
            });
        }

        if self.version.is_empty() {
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

        // Validate each address
        for address in &self.addresses {
            address.validate()?;
        }

        Ok(())
    }

    pub fn addresses(&self) -> &[Address] {
        &self.addresses
    }

    pub fn first_address(&self) -> &Address {
        &self.addresses[0]
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn public_key_type(&self) -> &str {
        &self.public_key_type
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }
}

impl Address {
    pub fn new(protocol: Protocol, address: String) -> Result<Self, Error> {
        let addr = Self { protocol, address };
        addr.validate()?;
        Ok(addr)
    }

    pub fn validate(&self) -> Result<(), Error> {
        // Parse host:port
        let parts: Vec<&str> = self.address.splitn(2, ':').collect();
        if parts.len() != 2 {
            return Err(Error::InvalidAddress {
                address: self.address.clone(),
            });
        }

        // Validate port is a valid number
        let port_str = parts[1];
        match port_str.parse::<u16>() {
            Ok(_) => Ok(()),
            Err(_) => Err(Error::InvalidAddress {
                address: self.address.clone(),
            }),
        }
    }

    pub fn host(&self) -> &str {
        self.address
            .split(':')
            .next()
            .expect("was validated at construction")
    }

    pub fn port(&self) -> u16 {
        self.address
            .split(':')
            .nth(1)
            .and_then(|p| p.parse().ok())
            .expect("was validated at construction")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_list_creation() {
        let address =
            Address::new(Protocol::Udp, "roughtime.example.com:2002".to_string()).unwrap();
        let server = Server::new(
            "Example Server".to_string(),
            "1".to_string(),
            "ed25519".to_string(),
            "base64encodedkey==".to_string(),
            vec![address],
        )
        .unwrap();

        let mut server_list = ServerList::new(vec![server], None, None).unwrap();
        assert_eq!(server_list.servers.len(), 1);

        let address2 = Address::new(Protocol::Tcp, "other.example.com:2003".to_string()).unwrap();
        let server2 = Server::new(
            "Other Server".to_string(),
            "1".to_string(),
            "ed25519".to_string(),
            "anotherkeyhere==".to_string(),
            vec![address2],
        )
        .unwrap();

        server_list.add_server(server2);
        assert_eq!(server_list.servers.len(), 2);
    }

    #[test]
    fn test_empty_server_list_fails() {
        match ServerList::new(vec![], None, None) {
            Err(Error::EmptyField { field }) => assert_eq!(field, "server list"),
            Err(e) => panic!("expected Error::EmptyField, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn test_address_parsing() {
        let address = Address::new(Protocol::Udp, "example.com:2002".to_string()).unwrap();
        assert_eq!(address.host(), "example.com");
        assert_eq!(address.port(), 2002);
    }

    #[test]
    fn test_invalid_addresses() {
        // Missing port
        match Address::new(Protocol::Udp, "invalid_address".to_string()) {
            Err(Error::InvalidAddress { address }) => assert_eq!(address, "invalid_address"),
            Err(e) => panic!("expected Error::InvalidAddress, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }

        // Invalid port
        match Address::new(Protocol::Udp, "example.com:not_a_port".to_string()) {
            Err(Error::InvalidAddress { address }) => assert_eq!(address, "example.com:not_a_port"),
            Err(e) => panic!("expected Error::InvalidAddress, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn test_json_serialization_roundtrip() {
        let address =
            Address::new(Protocol::Udp, "roughtime.example.com:2002".to_string()).unwrap();
        let server = Server::new(
            "Example Server".to_string(),
            "1".to_string(),
            "ed25519".to_string(),
            "base64encodedkey==".to_string(),
            vec![address],
        )
        .unwrap();
        let servers = vec![server];
        let server_list = ServerList::new(servers, None, None).unwrap();

        let json = server_list.to_json().unwrap();
        let parsed: ServerList = ServerList::from_json(&json).unwrap();

        assert_eq!(parsed.servers.len(), 1);
        assert_eq!(parsed.servers[0].name, "Example Server");
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
                "version": "1",
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
        let json = r#"{
            "servers": [{
                "name": "Server",
                "version": "1",
                "publicKeyType": "ed25519",
                "publicKey": "key==",
                "addresses": [{"protocol": "udp", "address": "no_port"}]
            }]
        }"#;
        match ServerList::from_json(json) {
            Err(Error::InvalidAddress { address }) => assert_eq!(address, "no_port"),
            Err(e) => panic!("expected Error::InvalidAddress, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }

        // Non-HTTPS source URL
        let json = r#"{
            "servers": [{
                "name": "Server",
                "version": "1",
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
        match Server::new(
            "".to_string(),
            "1".to_string(),
            "ed25519".to_string(),
            "key==".to_string(),
            vec![Address::new(Protocol::Udp, "example.com:2002".to_string()).unwrap()],
        ) {
            Err(Error::EmptyField { field }) => assert_eq!(field, "name"),
            Err(e) => panic!("expected Error::EmptyField, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }

        // Empty addresses
        match Server::new(
            "Server".to_string(),
            "1".to_string(),
            "ed25519".to_string(),
            "key==".to_string(),
            vec![],
        ) {
            Err(Error::EmptyField { field }) => assert!(field.contains("addresses")),
            Err(e) => panic!("expected Error::EmptyField, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }

    #[test]
    fn test_sources_validation() {
        let address = Address::new(Protocol::Udp, "example.com:2002".to_string()).unwrap();
        let server = Server::new(
            "Server".to_string(),
            "1".to_string(),
            "ed25519".to_string(),
            "key==".to_string(),
            vec![address],
        )
        .unwrap();

        // Valid HTTPS sources
        let result = ServerList::new(
            vec![server.clone()],
            Some(vec!["https://example.com/list.json".to_string()]),
            None,
        );
        assert!(result.is_ok());

        // Invalid HTTP source
        match ServerList::new(
            vec![server.clone()],
            Some(vec!["http://example.com/list.json".to_string()]),
            None,
        ) {
            Err(Error::InvalidUrl { reason }) => assert!(reason.contains("HTTPS scheme")),
            Err(e) => panic!("expected Error::InvalidUrl, got {e:?}"),
            Ok(_) => panic!("expected validation to fail"),
        }
    }
}
