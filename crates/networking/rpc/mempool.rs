use std::collections::HashMap;

use ethrex_common::{Address, H256};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{rpc::RpcApiContext, types::transaction::RpcTransaction, utils::RpcErr};

/// Maps account sender to its transactions indexed by nonce
type MempoolContentEntry = HashMap<Address, HashMap<u64, RpcTransaction>>;

/// Full content of the mempool
/// Transactions are grouped by sender and indexed by nonce
#[derive(Serialize, Deserialize)]
pub struct MempoolContent {
    pub pending: MempoolContentEntry,
    pub queued: MempoolContentEntry,
}

#[derive(Serialize, Deserialize)]
struct MempoolStatus {
    pending: String,
    queued: String,
}

/// Handling of rpc endpoint `mempool_content`
pub async fn content(context: RpcApiContext) -> Result<Value, RpcErr> {
    let transactions = context.blockchain.mempool.content()?;
    // Group transactions by sender and nonce and map them to rpc transactions
    let mut mempool_content = MempoolContentEntry::new();
    for tx in transactions {
        let sender_entry = mempool_content.entry(tx.sender()?).or_default();
        sender_entry.insert(
            tx.nonce(),
            RpcTransaction::build(tx, None, H256::zero(), None)?,
        );
    }
    let response = MempoolContent {
        pending: mempool_content,
        // We have no concept of "queued" transactions yet so we will leave this empty
        queued: MempoolContentEntry::new(),
    };
    Ok(serde_json::to_value(response)?)
}

pub async fn status(context: RpcApiContext) -> Result<Value, RpcErr> {
    let pending = context.blockchain.mempool.status()?;
    // We have no concept of "queued" transactions yet so we will leave this as 0
    let queued = 0;

    let response = MempoolStatus {
        pending: format!("{pending:#x}"),
        queued: format!("{queued:#x}"),
    };

    Ok(serde_json::to_value(response)?)
}
