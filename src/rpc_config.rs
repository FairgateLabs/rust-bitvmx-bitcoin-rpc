use bitcoin::Network;
use serde::Deserialize;

#[derive(Clone, Debug, Deserialize)]
pub struct RpcConfig {
    pub network: Network,
    pub url: String,
    pub username: String,
    pub password: String,
    pub wallet: String,
}
