# BitVMX Bitcoin RPC

BitVMX Bitcoin RPC is a Rust library that provides a convenient interface for interacting with a Bitcoin Core node.
It uses the [`bitcoincore-rpc`](https://crates.io/crates/bitcoincore-rpc) crate and provides additional abstractions and helper functions for easier interaction.

## Methods

- `BitcoinClient::new(url, user, pass)` - Connect to a Bitcoin Core node.
- `get_best_block()` - Get the current best block height.
- `get_block_by_height(height)` - Get block info by height.
- `get_block_by_hash(hash)` - Get block info by hash.
- `get_block_id_by_height(height)` - Get block hash by height.
- `get_blockchain_info()` - Get blockchain info.
- `tx_exists(txid)` - Check if a transaction exists.
- `get_raw_transaction_info(txid)` - Get raw transaction details.
- `get_transaction(txid)` - Get transaction by txid.
- `send_transaction(tx)` - Send a raw transaction.
- `fund_address(address, amount)` - Fund an address.
- `get_tx_out(txid, vout)` - Get UTXO details.
- `mine_blocks_to_address(num_blocks, address)` - Mine blocks to an address.
- `invalidate_block(hash)` - Invalidate a block.
- `init_wallet(wallet_name)` - Create and initialize a wallet.
- `get_new_address(pk, network)` - Generate a new address from a public key.
- `estimate_smart_fee()` - Estimate transaction fee rate.


## Usage

#### Connecting to a Bitcoin Core node

```rust
use bitvmx_bitcoin_rpc::BitcoinClient;

let client = BitcoinClient::new(
    "http://127.0.0.1:18443",
    "user",
    "password"
)?
```

#### Getting basic blockchain data
```rust 
let height = client.get_best_block()?;

let info = client.get_blockchain_info()?;

let block_info = client.get_block_by_height(&100)?;

let block_hash = client.get_block_id_by_height(&100)?;

let block = client.get_block_by_hash(&block_hash)?;

```

#### Sending and retrieving transactions
```rust 
let address = Address::from_str("bcrt1...")?;
let amount = Amount::from_sat(10_000);

let (tx, vout) = client.fund_address(&address, amount)?;

let txid = client.send_transaction(&tx)?;

let exists = client.tx_exists(&txid);
```

#### Wallet operations
```rust 
let address = client.init_wallet("test_wallet")?;

let new_address = client.get_new_address(public_key, bitcoin::Network::Regtest);
```

#### Mining blocks (regtest only)
```rust 
client.mine_blocks_to_address(1, &address)?;
```

#### Estimating fees
```rust 
let fee_rate = client.estimate_smart_fee()?
```

## Development Setup

1. Clone the repository
2. Install dependencies: `cargo build`