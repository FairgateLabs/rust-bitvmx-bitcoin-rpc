# BitVMX Bitcoin RPC

BitVMX Bitcoin RPC is a Rust library that provides a convenient interface for interacting with a Bitcoin Core node.
It is built on the [`jsonrpc`](https://crates.io/crates/jsonrpc) crate for transport and the [`corepc-types`](https://crates.io/crates/corepc-types) crate for typed responses, and provides additional abstractions and helper functions for easier interaction.

## ⚠️ Disclaimer

This library is currently under development and may not be fully stable.
It is not production-ready, has not been audited, and future updates may introduce breaking changes without preserving backward compatibility.

## Modules

- `bitcoin_client` - `BitcoinClient` and the `BitcoinClientApi` trait with every method. The trait is annotated with `#[automock]`, so `MockBitcoinClientApi` is available to mock the client in other crates.
- `rpc_config` - `RpcConfig`, the node URL, credentials, network and wallet, deserializable from config files.
- `errors` - `BitcoinClientError`, with `is_not_found()` and `is_node_unreachable()` helpers.
- `reqwest_https` - `ReqwestHttpsTransport`, the HTTP(S) transport with connection pooling. It implements the `jsonrpc` 0.21 `Transport` trait used by this crate and the `jsonrpc` 0.18 one used by BDK.
- `types` - `BlockHeight` and `BlockInfo`.

The `corepc_types` and `jsonrpc` crates are re-exported.

## Methods

### Chain
- `get_tip_height()` - Height of the chain tip.
- `get_block_by_height(height)` - Block at a height, with its hash and the hash of its parent.
- `get_block_id_by_height(height)` - Hash of the block at a height.
- `get_block_by_hash(hash)` - Full block.
- `get_block_header_info(hash)` - Block header with height and confirmations.
- `get_blockchain_info()` - Chain name, height and sync state.
- `is_txindex_enabled()` - Whether the node runs with `-txindex`.
- `invalidate_block(hash)` - Invalidate a block (regtest).

### Transactions
- `tx_exists(txid)` - Whether the node knows the transaction.
- `get_transaction(txid)` - Transaction by txid, `None` when the node cannot return it.
- `get_raw_transaction_info(txid)` - Verbose transaction details, `None` when the node does not know the transaction.
- `get_raw_transaction_verbosity_two(txid)` - Transaction with verbosity 2 details as JSON. *Requires Bitcoin Core 25.0 or higher.*
- `get_tx_confirmations(txid)` - `None` when not in the mempool nor the active chain, `Some(0)` in the mempool, `Some(n)` confirmed. *Requires `-txindex`.*
- `get_tx_out(txid, vout)` - Confirmed unspent output.
- `is_utxo_spent(txid, vout, include_mempool)` - Whether the output is not in the UTXO set.
- `send_transaction(tx)` - Broadcast a transaction.

### Mempool
- `estimate_smart_fee()` - Fee rate in sat/vB for the next block, 1 sat/vB when the node has no estimate.
- `get_mempool_entry(txid)` - Mempool entry, `None` when the transaction is not in the mempool.
- `get_raw_mempool()` - Txids in the mempool.
- `check_in_mempool(txid)` - Whether the transaction is in the mempool.

### Wallet and mining
- `fund_address(address, amount)` - Send to an address from the wallet and mine one block (regtest).
- `mine_blocks(num_blocks)` - Mine blocks to an address no wallet owns (regtest).
- `mine_blocks_to_address(num_blocks, address)` - Mine blocks to an address (regtest).
- `get_new_address(pk, network)` - P2WPKH address of a public key, computed locally.
- `init_wallet(wallet_name)` - Create the wallet if needed and return a new address from it.
- `create_wallet_only(wallet_name)` - Create the wallet if needed.

### Testing (`testing` feature)
Regtest helpers enabled with `features = ["testing"]`

## Usage

#### Connecting to a Bitcoin Core node

```rust
use bitvmx_bitcoin_rpc::bitcoin_client::{BitcoinClient, BitcoinClientApi};
use redact::Secret;

let client = BitcoinClient::new(
    &Secret::new("http://127.0.0.1:18443".to_string()),
    &Secret::new("user".to_string()),
    &Secret::new("password".to_string()),
)?;
```

From an `RpcConfig`, or connected to a specific wallet:

```rust
let client = BitcoinClient::new_from_config(&rpc_config)?;

let client = BitcoinClient::new_with_wallet(&url, &user, &pass, "test_wallet")?;
```

#### Getting basic blockchain data
```rust
let height = client.get_tip_height()?;

let info = client.get_blockchain_info()?;

let block_info = client.get_block_by_height(&100)?;

let block_hash = client.get_block_id_by_height(&100)?;

let block = client.get_block_by_hash(&block_hash)?;
```

#### Sending and retrieving transactions
```rust
let address = Address::from_str("bcrt1...")?.assume_checked();
let amount = Amount::from_sat(10_000);

let (tx, vout) = client.fund_address(&address, amount)?;

let exists = client.tx_exists(&tx.compute_txid());

let txid = client.send_transaction(&signed_tx)?;
```

#### Handling errors
```rust
match client.get_tx_out(&txid, 0) {
    Ok(out) => println!("Unspent: {}", out.tx_out.value),
    Err(e) if e.is_node_unreachable() => println!("Node is down"),
    Err(e) => return Err(e.into()),
}
```

#### Wallet operations
```rust
let address = client.init_wallet("test_wallet")?;

let new_address = client.get_new_address(public_key, bitcoin::Network::Regtest)?;
```

#### Mining blocks (regtest only)
```rust
client.mine_blocks_to_address(1, &address)?;
```

#### Estimating fees
```rust
let fee_rate = client.estimate_smart_fee()?;
```

#### Mocking the client in tests
```rust
use bitvmx_bitcoin_rpc::bitcoin_client::MockBitcoinClientApi;

let mut mock = MockBitcoinClientApi::new();
mock.expect_get_tip_height().returning(|| Ok(100));
```

## Development Setup

1. Clone the repository
2. Build: `cargo build`
3. Run the tests: `cargo test`. The integration tests start a regtest node in Docker, so Docker must be running. The `testing` helpers are always enabled for tests.

## Contributing
Contributions are welcome! Please open an issue or submit a pull request on GitHub.

## License

This project is licensed under the MIT License - see [LICENSE](LICENSE) file for details.

---

## 🧩 Part of the BitVMX Ecosystem

This repository is a component of the **BitVMX Ecosystem**, an open platform for disputable computation secured by Bitcoin.  
You can find the index of all BitVMX open-source components at [**FairgateLabs/BitVMX**](https://github.com/FairgateLabs/BitVMX).

---
