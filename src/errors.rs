use bitcoin::hex::HexToArrayError;
use thiserror::Error;

/// Error code Bitcoin Core returns when the requested transaction is not in the mempool or the transaction index.
const RPC_NOT_FOUND: i32 = -5;

#[derive(Error, Debug)]
pub enum BitcoinClientError {
    #[error("Invalid block height")]
    InvalidHeight,

    #[error("Error parsing address {0}")]
    ParseAddressError(#[from] bitcoin::address::ParseError),

    #[error("Error creating client {0}")]
    NewClientError(#[from] crate::reqwest_https::Error),

    #[error("Rpc error {0}")]
    RpcError(#[from] jsonrpc::Error),

    /// The node answered, but its answer could not be turned into the expected type.
    #[error("Unexpected node response: {0}")]
    InvalidResponse(String),

    #[error("Invalid block hash {0}")]
    InvalidBlockHash(#[from] HexToArrayError),

    #[error("Failed to fund address {error}")]
    FailedToFundAddress { error: String },

    #[error("Failed to get transaction details {error} ")]
    FailedToGetTransactionDetails { error: String },

    #[error("Failed to get tx output {error}")]
    FailedToGetTxOutput { error: String },

    #[error("Failed to send transaction {error} ")]
    FailedToSendTransaction { error: String },

    #[error("Failed to mine blocks {error}")]
    FailedToMineBlocks { error: String },

    #[error("Failed to create wallet {error}")]
    FailedToCreateWallet { error: String },

    #[error("Failed to list wallets {error}")]
    FailedToListWallets { error: String },

    #[error("Failed to get new address {error}")]
    FailedToGetNewAddress { error: String },

    #[error("Invalid network")]
    InvalidNetwork,

    #[error("Failed to load wallet {error}")]
    FailedToLoadWallet { error: String },

    #[error("Failed to invalidate block {error}")]
    FailedToInvalidateBlock { error: String },

    #[error("Invalid wallet name: {wallet_name}")]
    InvalidWalletName { wallet_name: String },

    #[error("Failed to convert PublicKey to CompressedPublicKey: {error}")]
    FailedToConvertPublicKey { error: String },
}

impl BitcoinClientError {
    /// True when the node answered that the requested transaction does not exist (code -5), as opposed to failing to
    /// answer. Bitcoin Core sends this answer with HTTP 500, and it still arrives here as an RPC error.
    pub fn is_not_found(&self) -> bool {
        matches!(
            self,
            BitcoinClientError::RpcError(jsonrpc::Error::Rpc(rpc_error)) if rpc_error.code == RPC_NOT_FOUND
        )
    }

    /// True when the node could not be reached (connection refused, timeout, DNS, or an HTTP failure without an RPC
    /// answer in its body), as opposed to the node answering with an error.
    pub fn is_node_unreachable(&self) -> bool {
        matches!(
            self,
            BitcoinClientError::RpcError(jsonrpc::Error::Transport(_))
        )
    }
}

/// Turns a failed corepc `into_model()` conversion into an error of this crate.
pub(crate) fn invalid_response(error: impl std::fmt::Display) -> BitcoinClientError {
    BitcoinClientError::InvalidResponse(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use corepc_types::v29::GetRawTransaction;

    /// An error answer from the node with the given RPC code.
    fn rpc_error(code: i32) -> BitcoinClientError {
        BitcoinClientError::RpcError(jsonrpc::Error::Rpc(jsonrpc::error::RpcError {
            code,
            message: "error".to_string(),
            data: None,
        }))
    }

    /// A failure to reach the node.
    fn unreachable() -> BitcoinClientError {
        BitcoinClientError::RpcError(jsonrpc::Error::Transport(Box::new(std::io::Error::other(
            "connection refused",
        ))))
    }

    // Only the node's "not found" answer (-5) is not found, and only a failure to reach the node is unreachable. Other
    // codes, like invalid parameter (-8) or the node still warming up (-28), are neither.
    #[test]
    fn not_found_and_unreachable_are_told_apart() {
        assert!(rpc_error(-5).is_not_found());
        assert!(!rpc_error(-5).is_node_unreachable());
        for code in [-8, -28] {
            assert!(!rpc_error(code).is_not_found());
            assert!(!rpc_error(code).is_node_unreachable());
        }
        assert!(unreachable().is_node_unreachable());
        assert!(!unreachable().is_not_found());
    }

    // A node answer that fails to convert, like a transaction that is not valid hex, becomes InvalidResponse and keeps
    // the conversion error in its message. It is neither a not-found answer nor an unreachable node.
    #[test]
    fn invalid_response_keeps_the_conversion_error() {
        let conversion = GetRawTransaction("not hex".to_string())
            .into_model()
            .unwrap_err();
        let error = invalid_response(&conversion);
        assert!(
            matches!(&error, BitcoinClientError::InvalidResponse(message) if *message == conversion.to_string())
        );
        assert_eq!(
            error.to_string(),
            format!("Unexpected node response: {conversion}")
        );
        assert!(!error.is_not_found());
        assert!(!error.is_node_unreachable());
    }
}
