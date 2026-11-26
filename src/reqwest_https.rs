//! HTTPS transport for Bitcoin Core JSON-RPC built on reqwest, which reuses connections between calls.
//!
//! TODO: The same transport serves two versions of the `jsonrpc` crate: 0.21, used by this crate's `BitcoinClient`, and 0.18,
//! used by BDK's `bdk_bitcoind_rpc` in the wallet. Each version defines its own `Transport` trait, so this file
//! implements both on the same struct. The 0.18 implementation can be removed once BDK moves to the newer `jsonrpc`.

use std::collections::HashMap;
use std::time::Duration;
use std::{error, fmt};

use reqwest::blocking::Client;

const DEFAULT_URL: &str = "http://localhost";
const DEFAULT_PORT: u16 = 8332; // The default RPC port for bitcoind.
const DEFAULT_TIMEOUT_SECONDS: u64 = 15;

/// An HTTPS transport that uses [`reqwest`] and is useful for running a bitcoind RPC client.
#[derive(Clone)]
pub struct ReqwestHttpsTransport {
    /// URL of the RPC server.
    url: String,
    /// Basic auth user and optional password.
    basic_auth: Option<(String, Option<String>)>,
    /// Headers to be added to the request.
    headers: HashMap<String, String>,
    /// HTTP client with connection pooling
    client: Client,
}

impl fmt::Debug for ReqwestHttpsTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The URL can carry an API key and the auth holds a password, so neither is printed.
        f.write_str("ReqwestHttpsTransport")
    }
}

fn build_client(timeout: Duration) -> Client {
    Client::builder()
        .timeout(timeout)
        .pool_idle_timeout(Duration::from_secs(30))
        .pool_max_idle_per_host(10)
        .build()
        .expect("Failed to create reqwest client")
}

impl Default for ReqwestHttpsTransport {
    fn default() -> Self {
        ReqwestHttpsTransport {
            url: format!("{}:{}", DEFAULT_URL, DEFAULT_PORT),
            basic_auth: None,
            headers: HashMap::new(),
            client: build_client(Duration::from_secs(DEFAULT_TIMEOUT_SECONDS)),
        }
    }
}

impl ReqwestHttpsTransport {
    /// Constructs a new [`ReqwestHttpsTransport`] with default parameters.
    pub fn new() -> Self {
        ReqwestHttpsTransport::default()
    }

    /// Returns a builder for [`ReqwestHttpsTransport`].
    pub fn builder() -> Builder {
        Builder::new()
    }

    fn request<R>(&self, req: impl serde::Serialize) -> Result<R, Error>
    where
        R: for<'a> serde::de::Deserialize<'a>,
    {
        let mut request = self.client.post(&self.url).json(&req);

        if let Some((user, pass)) = &self.basic_auth {
            request = request.basic_auth(user, pass.as_ref());
        }

        for (key, value) in &self.headers {
            request = request.header(key, value);
        }

        let response = request.send()?;
        let status = response.status();
        let body = response.text()?;

        // Bitcoin Core commonly returns JSON-RPC errors with HTTP 500. Parse the body before
        // rejecting the HTTP status so callers receive the useful RPC error (for example, -5 for
        // an unknown transaction). A non-success response without a valid RPC body remains an
        // HTTP transport failure.
        match serde_json::from_str(&body) {
            Ok(response) => Ok(response),
            Err(_) if !status.is_success() => Err(Error::Http(HttpError {
                status_code: status.as_u16() as i32,
                body,
            })),
            Err(error) => Err(Error::Json(error)),
        }
    }
}

// Used by this crate's BitcoinClient.
impl jsonrpc::Transport for ReqwestHttpsTransport {
    fn send_request(&self, req: jsonrpc::Request) -> Result<jsonrpc::Response, jsonrpc::Error> {
        Ok(self.request(req)?)
    }

    fn send_batch(
        &self,
        reqs: &[jsonrpc::Request],
    ) -> Result<Vec<jsonrpc::Response>, jsonrpc::Error> {
        Ok(self.request(reqs)?)
    }

    fn fmt_target(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

// Used by the wallet, whose BDK version still builds its client from jsonrpc 0.18.
impl jsonrpc_v18::Transport for ReqwestHttpsTransport {
    fn send_request(
        &self,
        req: jsonrpc_v18::Request,
    ) -> Result<jsonrpc_v18::Response, jsonrpc_v18::Error> {
        Ok(self.request(req)?)
    }

    fn send_batch(
        &self,
        reqs: &[jsonrpc_v18::Request],
    ) -> Result<Vec<jsonrpc_v18::Response>, jsonrpc_v18::Error> {
        Ok(self.request(reqs)?)
    }

    fn fmt_target(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.url)
    }
}

/// Builder for simple bitcoind [`ReqwestHttpsTransport`].
#[derive(Clone, Debug)]
pub struct Builder {
    tp: ReqwestHttpsTransport,
}

impl Builder {
    /// Constructs a new [`Builder`] with default configuration and the URL to use.
    pub fn new() -> Builder {
        Builder {
            tp: ReqwestHttpsTransport::new(),
        }
    }

    /// Sets the timeout after which requests will abort if they aren't finished.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.tp.client = build_client(timeout);
        self
    }

    /// Sets the URL of the server to the transport.
    pub fn url(mut self, url: &str) -> Result<Self, Error> {
        self.tp.url = url.to_owned();
        Ok(self)
    }

    /// Adds authentication information to the transport.
    pub fn basic_auth(mut self, user: String, pass: Option<String>) -> Self {
        self.tp.basic_auth = Some((user, pass));
        self
    }

    /// Adds Headers information to the transport.
    pub fn header(mut self, key: String, value: String) -> Self {
        self.tp.headers.insert(key, value);
        self
    }

    /// Builds the final [`ReqwestHttpsTransport`].
    pub fn build(self) -> ReqwestHttpsTransport {
        self.tp
    }
}

impl Default for Builder {
    fn default() -> Self {
        Builder::new()
    }
}

/// An HTTP error.
#[derive(Debug)]
pub struct HttpError {
    /// Status code of the error response.
    pub status_code: i32,
    /// Raw body of the error response.
    pub body: String,
}

impl fmt::Display for HttpError {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        write!(f, "status: {}, body: {}", self.status_code, self.body)
    }
}

impl error::Error for HttpError {}

/// Error that can happen when sending requests.
#[non_exhaustive]
#[derive(Debug)]
pub enum Error {
    /// JSON parsing error.
    Json(serde_json::Error),
    /// Reqwest error.
    Reqwest(reqwest::Error),
    /// HTTP error that does not contain valid JSON as body.
    Http(HttpError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> Result<(), fmt::Error> {
        match *self {
            Error::Json(ref e) => write!(f, "parsing JSON failed: {}", e),
            Error::Reqwest(ref e) => write!(f, "reqwest: {}", e),
            Error::Http(ref e) => write!(f, "http ({})", e),
        }
    }
}

impl error::Error for Error {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        use self::Error::*;

        match *self {
            Json(ref e) => Some(e),
            Reqwest(ref e) => Some(e),
            Http(ref e) => Some(e),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Json(e)
    }
}

impl From<reqwest::Error> for Error {
    fn from(e: reqwest::Error) -> Self {
        Error::Reqwest(e)
    }
}

impl From<Error> for jsonrpc::Error {
    fn from(e: Error) -> jsonrpc::Error {
        match e {
            Error::Json(e) => jsonrpc::Error::Json(e),
            e => jsonrpc::Error::Transport(Box::new(e)),
        }
    }
}

impl From<Error> for jsonrpc_v18::Error {
    fn from(e: Error) -> jsonrpc_v18::Error {
        match e {
            Error::Json(e) => jsonrpc_v18::Error::Json(e),
            e => jsonrpc_v18::Error::Transport(Box::new(e)),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn works_as_both_jsonrpc_transports() {
        // Port 0 never accepts connections, so each call fails inside this transport after the client accepted it.
        let transport = ReqwestHttpsTransport::builder()
            .url("http://127.0.0.1:0")
            .unwrap()
            .build();
        let v21 =
            jsonrpc::Client::with_transport(transport.clone()).call::<u64>("getblockcount", None);
        let v18 = jsonrpc_v18::Client::with_transport(transport).call::<u64>("getblockcount", None);
        assert!(
            matches!(v21, Err(jsonrpc::Error::Transport(_))),
            "got {v21:?}"
        );
        assert!(
            matches!(v18, Err(jsonrpc_v18::Error::Transport(_))),
            "got {v18:?}"
        );
    }

    #[test]
    fn debug_does_not_print_url_or_auth() {
        let transport = ReqwestHttpsTransport::builder()
            .url("https://node.example/secret-key")
            .unwrap()
            .basic_auth("user".into(), Some("secret-pass".into()))
            .build();
        assert!(!format!("{transport:?}").contains("secret"));
    }
}
