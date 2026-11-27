mod common;

use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, Network};
use bitvmx_bitcoin_rpc::{bitcoin_client::BitcoinClientApi, errors::BitcoinClientError};
use common::{TestNode, START_BLOCKS};

// Every way of reading the tip block (by height, by hash, header only, chain info) returns the same block.
#[test]
fn chain_reads_agree_on_the_tip() {
    let node = TestNode::start();
    let client = &node.client;

    let tip = node.tip();
    assert_eq!(u64::from(tip), START_BLOCKS);
    assert_eq!(client.get_block_count().unwrap(), START_BLOCKS);

    let hash = client.get_block_id_by_height(&tip).unwrap();
    assert_eq!(client.get_best_block_hash().unwrap(), hash);

    let info = client.get_block_by_height(&tip).unwrap().unwrap();
    assert_eq!(info.hash, hash);
    assert_eq!(info.height, tip);
    assert_eq!(
        info.prev_hash,
        client.get_block_id_by_height(&(tip - 1)).unwrap()
    );
    assert_eq!(info.txs.len(), 1, "only the coinbase");

    let block = client.get_block_by_hash(&hash).unwrap();
    assert_eq!(block.block_hash(), hash);
    assert_eq!(block.txdata, info.txs);

    let header = client.get_block_header_info(&hash).unwrap();
    assert_eq!(header.height, tip);
    assert_eq!(header.confirmations, 1);

    let chain = client.get_blockchain_info().unwrap();
    assert_eq!(chain.chain, Network::Regtest);
    assert_eq!(chain.blocks, tip);

    // The node in the tests runs with -txindex.
    assert!(client.is_txindex_enabled().unwrap());
}

// A height above the tip or an unknown hash is an error from the node.
#[test]
fn missing_blocks_are_errors() {
    let node = TestNode::start();
    let client = &node.client;
    let above_tip = node.tip() + 1;
    let unknown = BlockHash::from_byte_array([0x22; 32]);

    assert!(client.get_block_id_by_height(&above_tip).is_err());
    assert!(client.get_block_by_height(&above_tip).is_err());
    assert!(client.get_block_by_hash(&unknown).is_err());
    assert!(client.get_block_header_info(&unknown).is_err());
    assert!(matches!(
        client.invalidate_block(&unknown),
        Err(BitcoinClientError::FailedToInvalidateBlock { .. })
    ));
}

// Invalidating the tip moves the chain back one block, and reconsidering it brings the block back as the tip.
#[test]
fn invalidate_and_reconsider_block() {
    let node = TestNode::start();
    let client = &node.client;
    let tip = node.tip();
    let hash = client.get_block_id_by_height(&tip).unwrap();

    client.invalidate_block(&hash).unwrap();
    assert_eq!(node.tip(), tip - 1);
    assert_eq!(
        client.get_block_header_info(&hash).unwrap().confirmations,
        -1
    );

    client.reconsider_block(&hash).unwrap();
    assert_eq!(node.tip(), tip);
    assert_eq!(client.get_best_block_hash().unwrap(), hash);
}
