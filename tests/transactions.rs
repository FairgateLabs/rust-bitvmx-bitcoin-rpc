mod common;

use bitcoin::{Amount, OutPoint};
use bitvmx_bitcoin_rpc::{bitcoin_client::BitcoinClientApi, errors::BitcoinClientError};
use common::{unknown_txid, TestNode};

// A txid the node does not know reads as "not found" (false, None or a not-found error), never as another failure.
#[test]
fn unknown_transaction_is_not_found() {
    let node = TestNode::start();
    let client = &node.client;
    let txid = unknown_txid();

    assert!(!client.tx_exists(&txid));
    assert!(client.get_transaction(&txid).unwrap().is_none());
    assert!(client.get_raw_transaction_info(&txid).unwrap().is_none());
    assert_eq!(client.get_tx_confirmations(&txid).unwrap(), None);
    assert!(client
        .get_raw_transaction_verbosity_two(&txid)
        .unwrap_err()
        .is_not_found());
    assert!(matches!(
        client.get_tx_out(&txid, 0),
        Err(BitcoinClientError::FailedToGetTxOutput { .. })
    ));
    assert!(client.is_utxo_spent(&txid, 0, true).unwrap());
}

// A transaction is seen in the mempool with 0 confirmations, then in a block with 1. Its output joins the chain UTXO
// set only once confirmed, while the mempool view sees it right away.
#[test]
fn transaction_from_mempool_to_block() {
    let node = TestNode::start();
    let client = &node.client;
    let (txid, vout) = node.send(50_000);

    assert!(client.tx_exists(&txid));
    assert_eq!(
        client
            .get_transaction(&txid)
            .unwrap()
            .unwrap()
            .compute_txid(),
        txid
    );
    assert_eq!(
        client
            .get_raw_transaction_info(&txid)
            .unwrap()
            .unwrap()
            .block_hash,
        None
    );
    assert_eq!(client.get_tx_confirmations(&txid).unwrap(), Some(0));
    assert_eq!(
        client.get_raw_transaction_verbosity_two(&txid).unwrap()["txid"],
        txid.to_string()
    );
    assert!(!client.is_utxo_spent(&txid, vout, true).unwrap());
    assert!(client.is_utxo_spent(&txid, vout, false).unwrap());
    assert!(client.get_tx_out(&txid, vout).is_err());

    node.mine(1);

    let tip_hash = client.get_block_id_by_height(&node.tip()).unwrap();
    assert_eq!(
        client
            .get_raw_transaction_info(&txid)
            .unwrap()
            .unwrap()
            .block_hash,
        Some(tip_hash)
    );
    assert_eq!(client.get_tx_confirmations(&txid).unwrap(), Some(1));
    assert!(!client.is_utxo_spent(&txid, vout, false).unwrap());
    let tx_out = client.get_tx_out(&txid, vout).unwrap();
    assert_eq!(tx_out.tx_out.value, Amount::from_sat(50_000));
    assert_eq!(tx_out.confirmations, 1);
}

// A broadcast spend marks its input as spent in the mempool view, and in the chain view once mined. A conflicting spend
// paying a lower fee is rejected by the node.
#[test]
fn send_transaction_spends_the_input() {
    let node = TestNode::start();
    let client = &node.client;
    let outpoint = node.fund_utxo(1_000_000);
    let spend = node.spend(outpoint, 900_000);
    let conflict = node.spend(outpoint, 950_000);

    assert_eq!(
        client.send_transaction(&spend).unwrap(),
        spend.compute_txid()
    );
    assert!(client
        .is_utxo_spent(&outpoint.txid, outpoint.vout, true)
        .unwrap());
    assert!(!client
        .is_utxo_spent(&outpoint.txid, outpoint.vout, false)
        .unwrap());
    assert!(matches!(
        client.send_transaction(&conflict),
        Err(BitcoinClientError::FailedToSendTransaction { .. })
    ));

    node.mine(1);
    assert!(client
        .is_utxo_spent(&outpoint.txid, outpoint.vout, false)
        .unwrap());
}

// A transaction whose block is reorged out, and that a conflicting transaction replaces in the new chain, is in neither
// the mempool nor the active chain. The txindex still points to the old block, which must not count as confirmed.
#[test]
fn reorged_out_transaction_has_no_confirmations() {
    let node = TestNode::start();
    let client = &node.client;
    let outpoint: OutPoint = node.fund_utxo(1_000_000);
    let original = node.spend(outpoint, 900_000);
    let replacement = node.spend(outpoint, 950_000);
    let (original_txid, replacement_txid) = (original.compute_txid(), replacement.compute_txid());

    let old_block = client
        .generate_block_with_txs(&node.address(), &[original])
        .unwrap();
    assert_eq!(
        client.get_tx_confirmations(&original_txid).unwrap(),
        Some(1)
    );

    client.invalidate_block(&old_block).unwrap();
    client
        .generate_block_with_txs(&node.address(), &[replacement])
        .unwrap();

    let info = client
        .get_raw_transaction_info(&original_txid)
        .unwrap()
        .unwrap();
    assert_eq!(info.block_hash, Some(old_block));
    assert_eq!(client.get_tx_confirmations(&original_txid).unwrap(), None);
    assert_eq!(
        client.get_tx_confirmations(&replacement_txid).unwrap(),
        Some(1)
    );
}
