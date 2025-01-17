use bitcoin::Network;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct RpcConfig {
    pub network: Network,
    pub url: String,
    pub username: String,
    pub password: String,
    pub wallet: String,
}
