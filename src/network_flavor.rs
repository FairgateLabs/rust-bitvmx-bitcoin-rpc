//! Which chain we are talking to, and what we are allowed to do with it.
//!
//! [`bitcoin::Network`] answers only half the question. It describes a chain's
//! *encoding identity* — address HRP, WIF prefix, BIP-44 coin type, chain magic — and
//! for mainnet, the testnets and a regtest node we own outright, that happens to imply
//! the *capability profile* too: whether we may mint blocks, whether the node exposes a
//! wallet, whether funds have to pre-exist.
//!
//! Simchain breaks the tie. It is `Regtest` for every encoding purpose and even reports
//! `chain == "regtest"` over RPC, but operationally it behaves like a live network:
//! blocks are produced by the simnet's own miners on their own schedule, and the
//! user-facing node runs with `-disablewallet`.
//!
//! [`NetworkFlavor`] is therefore a superset of `Network` — every variant it has, plus
//! `Simchain` — and it is the type configuration and run-target selection use.
//!
//! It deliberately does **not** implement `Deref<Target = Network>` or any implicit
//! conversion. Encoding access goes through [`NetworkFlavor::bitcoin_network`], which
//! is explicit on purpose: the moment a flavor can silently stand in for a `Network`,
//! the two questions collapse back into one and simchain becomes indistinguishable from
//! regtest again.

use std::{fmt, str::FromStr, time::Duration};

use bitcoin::Network;
use serde::Deserialize;

/// Environment variable naming the run target.
///
/// Deliberately **not** `BITVMX_ENV`: `bitvmx-settings` already owns that name and
/// reads it as a *config file path* (`settings::load()` falls back to it when no
/// `--configuration` argument is given). Overloading it would make
/// `BITVMX_NETWORK_FLAVOR=simchain` break every `Config::new(None)` call site, and would make
/// this function panic for anyone already setting it to a path.
pub const NETWORK_ENV_VAR: &str = "BITVMX_NETWORK_FLAVOR";

/// A Bitcoin network, plus the simnets that `Network` cannot express.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NetworkFlavor {
    /// Bitcoin mainnet.
    Bitcoin,
    /// Bitcoin testnet3.
    #[serde(alias = "testnet3")]
    Testnet,
    /// Bitcoin testnet4.
    Testnet4,
    /// Bitcoin signet.
    Signet,
    /// A regtest node we own outright: we spawn it, mine on it, use its wallet.
    #[default]
    Regtest,
    /// A simchain simnet: regtest encoding, live-network behavior. Mining is external
    /// and there is no node wallet, so funds must already exist on chain.
    Simchain,
}

/// Returned when a string does not name a known network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseNetworkFlavorError(String);

impl fmt::Display for ParseNetworkFlavorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "unrecognized network {:?}; expected one of: {}",
            self.0,
            NetworkFlavor::ALL
                .iter()
                .map(|n| n.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )
    }
}

impl std::error::Error for ParseNetworkFlavorError {}

impl NetworkFlavor {
    pub const ALL: [NetworkFlavor; 6] = [
        NetworkFlavor::Bitcoin,
        NetworkFlavor::Testnet,
        NetworkFlavor::Testnet4,
        NetworkFlavor::Signet,
        NetworkFlavor::Regtest,
        NetworkFlavor::Simchain,
    ];

    // -- selection ----------------------------------------------------------

    /// Read the run target from [`NETWORK_ENV_VAR`].
    ///
    /// Three cases:
    ///
    /// - **unset**, or set to only whitespace: [`NetworkFlavor::Regtest`]. Callers that
    ///   never heard of this variable keep the behavior they always had.
    /// - **a recognized name**: that flavor.
    /// - **anything else**: panic — see below.
    ///
    /// # Panics
    ///
    /// If the variable holds a non-empty value that names no known network. A typo such
    /// as `BITVMX_NETWORK_FLAVOR=simchian` must never quietly fall back to regtest: the regtest
    /// path spawns its own bitcoind and mines blocks on demand, which is exactly the
    /// behavior the caller was trying to avoid.
    pub fn from_env() -> Self {
        Self::resolve(std::env::var(NETWORK_ENV_VAR).ok().as_deref())
            .unwrap_or_else(|e| panic!("{}: {e}", NETWORK_ENV_VAR))
    }

    /// The decision behind [`NetworkFlavor::from_env`], without touching the process
    /// environment.
    ///
    /// Split out so the unset / empty / typo cases can be tested directly; reading a
    /// global inside a test would race the other tests in this binary.
    fn resolve(raw: Option<&str>) -> Result<Self, ParseNetworkFlavorError> {
        match raw {
            None => Ok(Self::default()),
            Some(v) if v.trim().is_empty() => Ok(Self::default()),
            Some(v) => Self::parse(v),
        }
    }

    pub fn parse(s: &str) -> Result<Self, ParseNetworkFlavorError> {
        match s.trim().to_ascii_lowercase().as_str() {
            "bitcoin" | "mainnet" => Ok(NetworkFlavor::Bitcoin),
            "testnet" | "testnet3" => Ok(NetworkFlavor::Testnet),
            "testnet4" => Ok(NetworkFlavor::Testnet4),
            "signet" => Ok(NetworkFlavor::Signet),
            "regtest" => Ok(NetworkFlavor::Regtest),
            "simchain" => Ok(NetworkFlavor::Simchain),
            _ => Err(ParseNetworkFlavorError(s.to_string())),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            NetworkFlavor::Bitcoin => "bitcoin",
            NetworkFlavor::Testnet => "testnet",
            NetworkFlavor::Testnet4 => "testnet4",
            NetworkFlavor::Signet => "signet",
            NetworkFlavor::Regtest => "regtest",
            NetworkFlavor::Simchain => "simchain",
        }
    }

    // -- encoding identity --------------------------------------------------

    /// Address HRP, WIF prefix, BIP-44 coin type, chain magic.
    ///
    /// Simchain maps to [`Network::Regtest`] because that is genuinely what it is at
    /// the consensus layer. Kept explicit rather than exposed through `Deref` or
    /// `From`, so that reaching for the encoding is always a visible decision.
    pub fn bitcoin_network(self) -> Network {
        match self {
            NetworkFlavor::Bitcoin => Network::Bitcoin,
            NetworkFlavor::Testnet => Network::Testnet,
            NetworkFlavor::Testnet4 => Network::Testnet4,
            NetworkFlavor::Signet => Network::Signet,
            NetworkFlavor::Regtest | NetworkFlavor::Simchain => Network::Regtest,
        }
    }

    /// Whether this is a simchain simnet.
    ///
    /// Prefer the intent-named capabilities below at call sites; this exists for the
    /// guard rails that must name simchain specifically.
    pub fn is_simchain(self) -> bool {
        self == NetworkFlavor::Simchain
    }

    // -- capabilities -------------------------------------------------------

    /// Whether we drive block production ourselves via `generatetoaddress`.
    ///
    /// False for simchain even though its node would serve the RPC:
    /// `generatetoaddress` is a *mining* call, not a wallet call, so a
    /// `-disablewallet` simchain node still answers it. This predicate is the only
    /// thing stopping us from silently mining a chain we do not own.
    pub fn can_mine_on_demand(self) -> bool {
        self == NetworkFlavor::Regtest
    }

    /// Whether the node exposes a usable wallet
    /// (`createwallet` / `sendtoaddress` / `getnewaddress`).
    pub fn has_node_wallet(self) -> bool {
        self == NetworkFlavor::Regtest
    }

    /// Whether a test harness starts and stops its own bitcoind for this target.
    pub fn spawns_own_bitcoind(self) -> bool {
        self == NetworkFlavor::Regtest
    }

    /// Whether funds must already exist on chain because we cannot mint them.
    pub fn needs_prefunded_wallet(self) -> bool {
        !self.can_mine_on_demand()
    }

    /// Whether this is a chain we run ourselves.
    ///
    /// Regtest and the simnets built on it: coins are worthless, keys live in the
    /// repository, funding is free, and interactive prompts are noise. Everything else
    /// — including signet — belongs to somebody else, so we ask before spending and
    /// read keys from the environment.
    ///
    /// This is the predicate that replaces the old `network == Network::Regtest`
    /// tests. Do **not** reach for [`NetworkFlavor::is_real_money`] instead: signet
    /// coins are worthless but signet is not ours, so the two differ exactly there.
    pub fn is_local_chain(self) -> bool {
        matches!(self, NetworkFlavor::Regtest | NetworkFlavor::Simchain)
    }

    /// Whether local databases can be wiped and rebuilt by rescanning.
    ///
    /// Same membership as [`NetworkFlavor::is_local_chain`]: our own chains are short
    /// and reproducible, so a full rescan is cheap.
    pub fn is_disposable_chain(self) -> bool {
        self.is_local_chain()
    }

    /// Whether coins on this chain are worth actual money.
    ///
    /// Narrower than "not ours": signet is play money but still somebody else's chain.
    /// For "may I mint funds / skip the prompt / use repo keys", use
    /// [`NetworkFlavor::is_local_chain`].
    pub fn is_real_money(self) -> bool {
        matches!(
            self,
            NetworkFlavor::Bitcoin | NetworkFlavor::Testnet | NetworkFlavor::Testnet4
        )
    }

    // -- config file selection ----------------------------------------------

    /// Prefix for config file and environment variable names.
    ///
    /// Empty for regtest, matching the existing unprefixed `op_1.yaml` convention.
    pub fn prefix(self) -> &'static str {
        match self {
            NetworkFlavor::Regtest => "",
            NetworkFlavor::Bitcoin => "mainnet",
            other => other.as_str(),
        }
    }

    /// Upper-case prefix for environment variable lookups, e.g. `SIMCHAIN`.
    pub fn env_prefix(self) -> String {
        match self {
            NetworkFlavor::Regtest => "REGTEST".to_string(),
            NetworkFlavor::Bitcoin => "MAINNET".to_string(),
            other => other.as_str().to_ascii_uppercase(),
        }
    }

    pub fn wallet_config(self) -> String {
        match self {
            NetworkFlavor::Regtest => "config/wallet_regtest.yaml".to_string(),
            other => format!("config/wallet_{}.yaml", other.prefix()),
        }
    }

    /// Config file stem for one operator, e.g. `simchain_op_1`.
    pub fn op_config(self, index: usize) -> String {
        match self {
            NetworkFlavor::Regtest => format!("op_{index}"),
            other => format!("{}_op_{index}", other.prefix()),
        }
    }

    /// Operator config stems shipped for this target.
    pub fn op_configs(self) -> Vec<String> {
        let count = match self {
            // Regtest and simchain both run the full four-operator committee.
            NetworkFlavor::Regtest | NetworkFlavor::Simchain => 4,
            // Only three operator configs exist for the live testnets.
            NetworkFlavor::Testnet | NetworkFlavor::Testnet4 => 3,
            // None ship for mainnet or signet.
            NetworkFlavor::Bitcoin | NetworkFlavor::Signet => 0,
        };
        (1..=count).map(|i| self.op_config(i)).collect()
    }

    /// Whether this repo ships config files for the target.
    pub fn has_configs(self) -> bool {
        !self.op_configs().is_empty()
    }

    /// Operator group name accepted by the client binary's `--op` argument.
    pub fn operator_group(self) -> String {
        match self {
            NetworkFlavor::Regtest => "all".to_string(),
            other => format!("all-{}", other.prefix()),
        }
    }

    // -- fees and timing ----------------------------------------------------

    /// Default fee rate in sat/vB for wallet-funded transactions.
    ///
    /// Simchain runs a transaction spammer that holds the mempool at a fee floor
    /// (15 sat/vB with the stock `.env`), so the 1 sat/vB used for the live networks
    /// would never confirm there.
    pub fn default_fee_rate(self) -> u64 {
        match self {
            NetworkFlavor::Regtest => 2,
            NetworkFlavor::Simchain => 20,
            NetworkFlavor::Bitcoin
            | NetworkFlavor::Testnet
            | NetworkFlavor::Testnet4
            | NetworkFlavor::Signet => 1,
        }
    }

    /// How often to poll for a new block while waiting for one.
    pub fn block_poll_interval(self) -> Duration {
        match self {
            NetworkFlavor::Regtest => Duration::from_millis(100),
            NetworkFlavor::Simchain => Duration::from_millis(500),
            NetworkFlavor::Testnet | NetworkFlavor::Testnet4 | NetworkFlavor::Signet => {
                Duration::from_secs(5)
            }
            // Blocks average ten minutes; polling faster just burns RPC calls.
            NetworkFlavor::Bitcoin => Duration::from_secs(60),
        }
    }

    /// How long to tolerate no new block before declaring the chain stalled.
    ///
    /// Generous relative to the expected interval: simchain's default cadence is a
    /// bounded Poisson process around 10s, and a stalled miner should surface as a
    /// clear timeout rather than a test that hangs forever.
    pub fn block_wait_timeout(self) -> Duration {
        match self {
            NetworkFlavor::Regtest => Duration::from_secs(60),
            NetworkFlavor::Simchain => Duration::from_secs(300),
            NetworkFlavor::Testnet | NetworkFlavor::Testnet4 | NetworkFlavor::Signet => {
                Duration::from_secs(3600)
            }
            NetworkFlavor::Bitcoin => Duration::from_secs(7200),
        }
    }
}

impl fmt::Display for NetworkFlavor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for NetworkFlavor {
    type Err = ParseNetworkFlavorError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::parse(s)
    }
}

/// Widening is lossless and unambiguous, so it is implicit.
///
/// The reverse is not: `NetworkFlavor::Simchain` and `NetworkFlavor::Regtest` both map
/// to `Network::Regtest`, so narrowing must stay an explicit
/// [`NetworkFlavor::bitcoin_network`] call.
impl From<Network> for NetworkFlavor {
    fn from(network: Network) -> Self {
        match network {
            Network::Bitcoin => NetworkFlavor::Bitcoin,
            Network::Testnet => NetworkFlavor::Testnet,
            Network::Testnet4 => NetworkFlavor::Testnet4,
            Network::Signet => NetworkFlavor::Signet,
            Network::Regtest => NetworkFlavor::Regtest,
            // `bitcoin::Network` is `#[non_exhaustive]`, so this arm is required even
            // though every variant above is covered. Whether rustc also considers it
            // unreachable depends on the build context, hence the `allow`: without the
            // arm the client crate fails to compile, with it a standalone build of this
            // crate warns. A new upstream network is not a simnet of ours, so refusing
            // loudly is the right behavior.
            #[allow(unreachable_patterns)]
            other => panic!("unsupported bitcoin network: {other:?}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regtest_is_the_default() {
        assert_eq!(NetworkFlavor::default(), NetworkFlavor::Regtest);
    }

    #[test]
    fn parse_accepts_every_known_name() {
        assert_eq!(NetworkFlavor::parse("regtest"), Ok(NetworkFlavor::Regtest));
        assert_eq!(NetworkFlavor::parse("simchain"), Ok(NetworkFlavor::Simchain));
        assert_eq!(NetworkFlavor::parse("testnet"), Ok(NetworkFlavor::Testnet));
        assert_eq!(NetworkFlavor::parse("testnet3"), Ok(NetworkFlavor::Testnet));
        assert_eq!(NetworkFlavor::parse("testnet4"), Ok(NetworkFlavor::Testnet4));
        assert_eq!(NetworkFlavor::parse("signet"), Ok(NetworkFlavor::Signet));
        assert_eq!(NetworkFlavor::parse("mainnet"), Ok(NetworkFlavor::Bitcoin));
        assert_eq!(NetworkFlavor::parse("bitcoin"), Ok(NetworkFlavor::Bitcoin));
    }

    #[test]
    fn parse_is_case_and_whitespace_insensitive() {
        assert_eq!(
            NetworkFlavor::parse("  SimChain \n"),
            Ok(NetworkFlavor::Simchain)
        );
    }

    #[test]
    fn resolve_covers_unset_empty_and_typo() {
        // Unset and empty both mean "caller said nothing" -> the default.
        assert_eq!(NetworkFlavor::resolve(None), Ok(NetworkFlavor::Regtest));
        assert_eq!(NetworkFlavor::resolve(Some("")), Ok(NetworkFlavor::Regtest));
        assert_eq!(NetworkFlavor::resolve(Some("   ")), Ok(NetworkFlavor::Regtest));

        assert_eq!(
            NetworkFlavor::resolve(Some("simchain")),
            Ok(NetworkFlavor::Simchain)
        );

        // A non-empty value that names nothing is an error, never a silent default.
        assert!(NetworkFlavor::resolve(Some("simchian")).is_err());
    }

    #[test]
    fn parse_rejects_typos_rather_than_defaulting() {
        // The whole point: `simchian` must not quietly become regtest and start mining.
        let msg = NetworkFlavor::parse("simchian").unwrap_err().to_string();
        assert!(msg.contains("simchian"), "{msg}");
        assert!(msg.contains("simchain"), "{msg}");
    }

    #[test]
    fn round_trips_through_as_str() {
        for flavor in NetworkFlavor::ALL {
            assert_eq!(NetworkFlavor::parse(flavor.as_str()), Ok(flavor));
        }
    }

    #[test]
    fn is_a_superset_of_bitcoin_network() {
        // Every Network widens into a flavor and narrows back unchanged.
        for network in [
            Network::Bitcoin,
            Network::Testnet,
            Network::Testnet4,
            Network::Signet,
            Network::Regtest,
        ] {
            let flavor = NetworkFlavor::from(network);
            assert_eq!(flavor.bitcoin_network(), network, "{network:?}");
        }
    }

    #[test]
    fn simchain_encodes_as_regtest_but_is_not_regtest() {
        assert_eq!(
            NetworkFlavor::Simchain.bitcoin_network(),
            Network::Regtest,
            "simchain must encode as regtest"
        );
        assert_ne!(NetworkFlavor::Simchain, NetworkFlavor::Regtest);
        // Narrowing is lossy, which is exactly why it stays explicit.
        assert_eq!(
            NetworkFlavor::Regtest.bitcoin_network(),
            NetworkFlavor::Simchain.bitcoin_network()
        );
    }

    #[test]
    fn only_regtest_may_mine_or_use_the_node_wallet() {
        assert!(NetworkFlavor::Regtest.can_mine_on_demand());
        assert!(NetworkFlavor::Regtest.has_node_wallet());
        assert!(NetworkFlavor::Regtest.spawns_own_bitcoind());
        assert!(!NetworkFlavor::Regtest.needs_prefunded_wallet());

        for flavor in NetworkFlavor::ALL {
            if flavor == NetworkFlavor::Regtest {
                continue;
            }
            assert!(!flavor.can_mine_on_demand(), "{flavor}");
            assert!(!flavor.has_node_wallet(), "{flavor}");
            assert!(!flavor.spawns_own_bitcoind(), "{flavor}");
            assert!(flavor.needs_prefunded_wallet(), "{flavor}");
        }
    }

    #[test]
    fn simchain_local_state_is_still_disposable() {
        assert!(NetworkFlavor::Simchain.is_disposable_chain());
        assert!(NetworkFlavor::Regtest.is_disposable_chain());
        assert!(!NetworkFlavor::Testnet.is_disposable_chain());
        assert!(!NetworkFlavor::Bitcoin.is_disposable_chain());
    }

    #[test]
    fn is_local_chain_is_regtest_plus_our_simnets() {
        // Pins the replacement for the old `network == Network::Regtest` tests.
        // Signet is the trap: worthless coins, but not our chain.
        assert!(NetworkFlavor::Regtest.is_local_chain());
        assert!(NetworkFlavor::Simchain.is_local_chain());
        for flavor in [
            NetworkFlavor::Testnet,
            NetworkFlavor::Testnet4,
            NetworkFlavor::Signet,
            NetworkFlavor::Bitcoin,
        ] {
            assert!(!flavor.is_local_chain(), "{flavor}");
        }
    }

    #[test]
    fn is_local_chain_and_is_real_money_differ_only_on_signet() {
        for flavor in NetworkFlavor::ALL {
            if flavor == NetworkFlavor::Signet {
                assert!(!flavor.is_local_chain() && !flavor.is_real_money());
            } else {
                assert_eq!(
                    flavor.is_local_chain(),
                    !flavor.is_real_money(),
                    "{flavor}"
                );
            }
        }
    }

    #[test]
    fn simchain_is_not_real_money() {
        assert!(!NetworkFlavor::Simchain.is_real_money());
        assert!(!NetworkFlavor::Regtest.is_real_money());
        assert!(NetworkFlavor::Testnet.is_real_money());
        assert!(NetworkFlavor::Testnet4.is_real_money());
        assert!(NetworkFlavor::Bitcoin.is_real_money());
    }

    #[test]
    fn simchain_fee_rate_clears_the_spam_floor() {
        // The stock simchain .env holds the mempool at 15 sat/vB.
        assert!(NetworkFlavor::Simchain.default_fee_rate() > 15);
        assert_eq!(NetworkFlavor::Testnet.default_fee_rate(), 1);
    }

    #[test]
    fn config_paths_match_the_files_on_disk() {
        assert_eq!(
            NetworkFlavor::Regtest.wallet_config(),
            "config/wallet_regtest.yaml"
        );
        assert_eq!(
            NetworkFlavor::Simchain.wallet_config(),
            "config/wallet_simchain.yaml"
        );
        assert_eq!(
            NetworkFlavor::Testnet4.wallet_config(),
            "config/wallet_testnet4.yaml"
        );

        assert_eq!(NetworkFlavor::Regtest.op_config(1), "op_1");
        assert_eq!(NetworkFlavor::Simchain.op_config(1), "simchain_op_1");
        assert_eq!(NetworkFlavor::Testnet.op_config(3), "testnet_op_3");

        assert_eq!(
            NetworkFlavor::Regtest.op_configs(),
            vec!["op_1", "op_2", "op_3", "op_4"]
        );
        assert_eq!(
            NetworkFlavor::Simchain.op_configs(),
            vec![
                "simchain_op_1",
                "simchain_op_2",
                "simchain_op_3",
                "simchain_op_4"
            ]
        );
        assert_eq!(
            NetworkFlavor::Testnet.op_configs(),
            vec!["testnet_op_1", "testnet_op_2", "testnet_op_3"]
        );

        assert_eq!(NetworkFlavor::Regtest.operator_group(), "all");
        assert_eq!(NetworkFlavor::Simchain.operator_group(), "all-simchain");
        assert_eq!(NetworkFlavor::Testnet.operator_group(), "all-testnet");
    }

    #[test]
    fn mainnet_is_selectable_even_though_no_configs_ship_for_it() {
        // The union example's utility commands (create_wallet, latency, explorer
        // links) only need an encoding and a prefix. Keep them working.
        assert_eq!(NetworkFlavor::Bitcoin.prefix(), "mainnet");
        assert_eq!(NetworkFlavor::Bitcoin.env_prefix(), "MAINNET");
        assert!(!NetworkFlavor::Bitcoin.has_configs());

        for flavor in [
            NetworkFlavor::Regtest,
            NetworkFlavor::Simchain,
            NetworkFlavor::Testnet,
            NetworkFlavor::Testnet4,
        ] {
            assert!(flavor.has_configs(), "{flavor}");
        }
    }

    #[test]
    fn deserializes_from_a_single_config_field() {
        // The merged design: one `network:` key, which cannot contradict itself.
        for (raw, expected) in [
            ("\"regtest\"", NetworkFlavor::Regtest),
            ("\"simchain\"", NetworkFlavor::Simchain),
            ("\"testnet\"", NetworkFlavor::Testnet),
            ("\"testnet3\"", NetworkFlavor::Testnet),
            ("\"testnet4\"", NetworkFlavor::Testnet4),
            ("\"bitcoin\"", NetworkFlavor::Bitcoin),
        ] {
            let got: NetworkFlavor = serde_json::from_str(raw).unwrap();
            assert_eq!(got, expected, "{raw}");
        }
    }
}
