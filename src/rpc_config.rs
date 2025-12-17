use bitcoin::Network;
use redact::Secret;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct RpcConfig {
    pub network: Network,
    pub url: Secret<String>,
    pub username: Secret<String>,
    pub password: Secret<String>,
    pub wallet: String,
}

impl RpcConfig {
    pub fn new(
        network: Network,
        url: String,
        username: String,
        password: String,
        wallet: String,
    ) -> Self {
        Self {
            network,
            url: Secret::new(url),
            username: Secret::new(username),
            password: Secret::new(password),
            wallet,
        }
    }
}
