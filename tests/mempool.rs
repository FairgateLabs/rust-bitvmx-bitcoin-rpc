mod common;

use bitcoin::Amount;
use bitvmx_bitcoin_rpc::bitcoin_client::BitcoinClientApi;
use common::{unknown_txid, TestNode};

// A broadcast transaction is in the mempool until it is mined. Prioritising it raises only the fee miners count for it.
// A fresh regtest node has no fee data, so the fee estimate falls back to 1 sat/vB.
#[test]
fn mempool_holds_a_transaction_until_mined() {
    let node = TestNode::start();
    let client = &node.client;
    assert_eq!(client.estimate_smart_fee().unwrap(), 1);
    assert!(client.get_mempool_entry(&unknown_txid()).unwrap().is_none());
    assert!(!client.check_in_mempool(&unknown_txid()).unwrap());

    let (txid, _) = node.send(50_000);
    assert_eq!(client.get_raw_mempool().unwrap(), vec![txid]);
    assert!(client.check_in_mempool(&txid).unwrap());
    let entry = client.get_mempool_entry(&txid).unwrap().unwrap().0;
    assert_eq!(entry.height, node.tip());

    client.prioritise_transaction(&txid, 1_000).unwrap();
    let fees = client.get_mempool_entry(&txid).unwrap().unwrap().0.fees;
    assert_eq!(fees.modified, fees.base + Amount::from_sat(1_000));

    node.mine(1);
    assert!(client.get_raw_mempool().unwrap().is_empty());
    assert!(client.get_mempool_entry(&txid).unwrap().is_none());
    assert!(!client.check_in_mempool(&txid).unwrap());
}
