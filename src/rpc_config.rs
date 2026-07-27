use bitcoin::Network;
use redact::Secret;
use serde::Deserialize;

pub use crate::network_flavor::NetworkFlavor;

#[derive(Clone, Debug, Deserialize)]
pub struct RpcConfig {
    /// Which chain this is, including simnets that [`Network`] cannot express.
    ///
    /// Named `flavor` rather than `network` on purpose. Almost every consumer — the
    /// key manager, the coordinator, the indexer, BDK — wants the plain
    /// [`bitcoin::Network`] and should get it from [`RpcConfig::network`] without ever
    /// learning that simnets exist. Reaching for this field means you are asking a
    /// capability question, and having to name it keeps that deliberate.
    ///
    /// The YAML key is still `network:`, so configuration files are unchanged and
    /// `network: simchain` is simply one of the accepted values.
    #[serde(rename = "network")]
    pub network_flavor: NetworkFlavor,

    pub url: Secret<String>,
    pub username: Secret<String>,
    pub password: Secret<String>,
    pub wallet: String,
}

impl RpcConfig {
    pub fn new(
        network: impl Into<NetworkFlavor>,
        url: String,
        username: String,
        password: String,
        wallet: String,
    ) -> Self {
        Self {
            network_flavor: network.into(),
            url: Secret::new(url),
            username: Secret::new(username),
            password: Secret::new(password),
            wallet,
        }
    }

    /// The plain Bitcoin network this config points at.
    ///
    /// This is what nearly everything wants: a simchain config reports
    /// [`Network::Regtest`] here, which is correct for addresses, keys and chain
    /// magic. Components that only encode and decode should use this and stay
    /// entirely unaware of simnets.
    pub fn network(&self) -> Network {
        self.network_flavor.bitcoin_network()
    }

    /// Alias for [`RpcConfig::network`], for call sites where the distinction from
    /// [`RpcConfig::flavor`] is worth spelling out.
    pub fn bitcoin_network(&self) -> Network {
        self.network()
    }

    pub fn is_simchain(&self) -> bool {
        self.network_flavor.is_simchain()
    }

    /// Whether we drive block production ourselves via `generatetoaddress`.
    pub fn can_mine_on_demand(&self) -> bool {
        self.network_flavor.can_mine_on_demand()
    }

    /// Whether the node exposes a usable wallet
    /// (`createwallet` / `sendtoaddress` / `getnewaddress`).
    pub fn has_node_wallet(&self) -> bool {
        self.network_flavor.has_node_wallet()
    }

    /// Whether funds must already exist on chain because we cannot mint them.
    pub fn needs_prefunded_wallet(&self) -> bool {
        self.network_flavor.needs_prefunded_wallet()
    }

    /// Whether the chain is disposable, so wiping local databases is safe.
    pub fn is_disposable_chain(&self) -> bool {
        self.network_flavor.is_disposable_chain()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(network: NetworkFlavor) -> RpcConfig {
        RpcConfig::new(
            network,
            "http://127.0.0.1:18443".to_string(),
            "foo".to_string(),
            "rpcpassword".to_string(),
            "test_wallet".to_string(),
        )
    }

    #[test]
    fn plain_regtest_keeps_every_capability() {
        let cfg = config(NetworkFlavor::Regtest);
        assert!(cfg.can_mine_on_demand());
        assert!(cfg.has_node_wallet());
        assert!(cfg.is_disposable_chain());
        assert!(!cfg.needs_prefunded_wallet());
        assert!(!cfg.is_simchain());
        assert_eq!(cfg.network(), Network::Regtest);
    }

    #[test]
    fn simchain_is_regtest_encoding_but_live_behavior() {
        let cfg = config(NetworkFlavor::Simchain);
        assert_eq!(cfg.network(), Network::Regtest);
        assert!(cfg.is_simchain());
        assert!(!cfg.can_mine_on_demand());
        assert!(!cfg.has_node_wallet());
        assert!(cfg.needs_prefunded_wallet());
        // Local state is still throwaway even though the chain is not ours to mine.
        assert!(cfg.is_disposable_chain());
    }

    #[test]
    fn live_networks_are_unaffected() {
        for network in [
            NetworkFlavor::Testnet,
            NetworkFlavor::Testnet4,
            NetworkFlavor::Bitcoin,
        ] {
            let cfg = config(network);
            assert!(!cfg.can_mine_on_demand());
            assert!(!cfg.has_node_wallet());
            assert!(cfg.needs_prefunded_wallet());
            assert!(!cfg.is_disposable_chain());
            assert!(!cfg.is_simchain());
        }
    }

    #[test]
    fn accepts_a_bitcoin_network_directly() {
        // Widening is implicit, so existing constructor calls keep compiling.
        let cfg = RpcConfig::new(
            Network::Regtest,
            "http://127.0.0.1:18443".to_string(),
            "foo".to_string(),
            "rpcpassword".to_string(),
            "test_wallet".to_string(),
        );
        assert_eq!(cfg.network_flavor, NetworkFlavor::Regtest);
    }

    // Deserialization is exercised through serde_json rather than serde_yaml: the
    // `rename_all` attribute is format-independent, and adding a dev-dependency here
    // would break the workspace's `paths` override. The YAML files themselves are
    // covered by tests/config_load.rs in the client.

    #[test]
    fn regtest_configs_deserialize_unchanged() {
        let cfg: RpcConfig = serde_json::from_str(
            r#"{"network":"regtest","url":"http://127.0.0.1:18443",
                "username":"foo","password":"rpcpassword","wallet":"test_wallet"}"#,
        )
        .unwrap();
        assert_eq!(cfg.network_flavor, NetworkFlavor::Regtest);
        assert!(cfg.can_mine_on_demand());
    }

    #[test]
    fn simchain_needs_only_the_network_field() {
        let cfg: RpcConfig = serde_json::from_str(
            r#"{"network":"simchain","url":"http://127.0.0.1:18443",
                "username":"foo","password":"rpcpassword","wallet":"test_wallet"}"#,
        )
        .unwrap();
        assert_eq!(cfg.network_flavor, NetworkFlavor::Simchain);
        assert!(!cfg.can_mine_on_demand());
        assert_eq!(cfg.network(), Network::Regtest);
    }
}
