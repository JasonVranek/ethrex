use std::{cmp::min, ops::Deref, sync::Arc, time::Duration};

use ethrex_blockchain::{fork_choice::apply_fork_choice, Blockchain};
use ethrex_common::{
    types::{Block, BlockNumber, Transaction},
    Address, H256, U256,
};
use ethrex_rlp::decode::RLPDecode;
use ethrex_rpc::{types::receipt::RpcLog, utils::get_withdrawal_hash, EthClient};
use ethrex_storage::Store;
use ethrex_storage_rollup::StoreRollup;
use keccak_hash::keccak;
use tokio::{sync::Mutex, time::sleep};
use tracing::{error, info};

use crate::{utils::helpers::is_withdrawal_l2, SequencerConfig};

use super::{
    errors::{BlockFetcherError, SequencerError},
    SequencerState,
};

pub struct BlockFetcher {
    eth_client: EthClient,
    on_chain_proposer_address: Address,
    store: Store,
    rollup_store: StoreRollup,
    blockchain: Arc<Blockchain>,
    sequencer_state: Arc<Mutex<SequencerState>>,
    fetch_interval_ms: u64,
    last_l1_block_fetched: U256,
    max_block_step: U256,
}

pub async fn start_block_fetcher(
    store: Store,
    blockchain: Arc<Blockchain>,
    sequencer_state: Arc<Mutex<SequencerState>>,
    rollup_store: StoreRollup,
    cfg: SequencerConfig,
) -> Result<(), SequencerError> {
    let mut block_fetcher = BlockFetcher::new(
        &cfg,
        store.clone(),
        rollup_store,
        blockchain,
        sequencer_state,
    )
    .await?;
    block_fetcher.run().await;
    Ok(())
}

impl BlockFetcher {
    pub async fn new(
        cfg: &SequencerConfig,
        store: Store,
        rollup_store: StoreRollup,
        blockchain: Arc<Blockchain>,
        sequencer_state: Arc<Mutex<SequencerState>>,
    ) -> Result<Self, BlockFetcherError> {
        let eth_client = EthClient::new_with_multiple_urls(cfg.eth.rpc_url.clone())?;
        let last_l1_block_fetched = eth_client
            .get_last_fetched_l1_block(cfg.l1_watcher.bridge_address)
            .await?
            .into();
        Ok(Self {
            eth_client: EthClient::new_with_multiple_urls(cfg.eth.rpc_url.clone())?,
            on_chain_proposer_address: cfg.l1_committer.on_chain_proposer_address,
            store,
            rollup_store,
            blockchain,
            sequencer_state,
            fetch_interval_ms: cfg.block_producer.block_time_ms,
            last_l1_block_fetched,
            max_block_step: cfg.l1_watcher.max_block_step, // TODO: block fetcher config
        })
    }

    pub async fn run(&mut self) {
        loop {
            if let Err(err) = self.main_logic().await {
                error!("Block Fetcher Error: {err}");
            }

            sleep(Duration::from_millis(self.fetch_interval_ms)).await;
        }
    }

    pub async fn main_logic(&mut self) -> Result<(), BlockFetcherError> {
        let sequencer_state_clone = self.sequencer_state.clone();
        let sequencer_state_mutex_guard = sequencer_state_clone.lock().await;
        match sequencer_state_mutex_guard.deref() {
            SequencerState::Sequencing => Ok(()),
            SequencerState::Following => self.fetch().await,
        }
    }

    async fn fetch(&mut self) -> Result<(), BlockFetcherError> {
        while !self.node_is_up_to_date().await? {
            info!("Node is not up to date. Syncing via L1");

            let last_l2_block_number_known = self.store.get_latest_block_number().await?;

            let last_l2_batch_number_known = self
                .rollup_store
                .get_batch_number_by_block(last_l2_block_number_known)
                .await?
                .ok_or(BlockFetcherError::InternalError(format!(
                    "Failed to get last batch number known for block {last_l2_block_number_known}"
                )))?;

            let last_l2_committed_batch_number = self
                .eth_client
                .get_last_committed_batch(self.on_chain_proposer_address)
                .await?;

            let l2_batches_behind = last_l2_committed_batch_number.checked_sub(last_l2_batch_number_known).ok_or(
                BlockFetcherError::InternalError(
                    "Failed to calculate batches behind. Last batch number known is greater than last committed batch number.".to_string(),
                ),
            )?;

            info!("Node is {l2_batches_behind} batches behind. Last batch number known: {last_l2_batch_number_known}, last committed batch number: {last_l2_committed_batch_number}");

            let batch_committed_logs = self.get_logs().await?;

            let mut missing_batches_logs = self.filter_logs(&batch_committed_logs).await?;

            missing_batches_logs.sort_by_key(|(_log, batch_number)| *batch_number);

            for (batch_committed_log, batch_number) in missing_batches_logs {
                let batch_commit_tx_calldata = self
                    .eth_client
                    .get_transaction_by_hash(batch_committed_log.transaction_hash)
                    .await?
                    .ok_or(BlockFetcherError::InternalError(format!(
                        "Failed to get the receipt for transaction {:x}",
                        batch_committed_log.transaction_hash
                    )))?
                    .data;

                let batch = Self::decode_batch_from_calldata(&batch_commit_tx_calldata)?;

                self.store_batch(&batch).await?;

                self.seal_batch(&batch, batch_number).await?;
            }

            sleep(Duration::from_millis(self.fetch_interval_ms)).await;
        }

        info!("Node is up to date");

        Ok(())
    }

    async fn node_is_up_to_date(&self) -> Result<bool, BlockFetcherError> {
        let last_committed_batch_number = self
            .eth_client
            .get_last_committed_batch(self.on_chain_proposer_address)
            .await?;

        self.rollup_store
            .contains_batch(&last_committed_batch_number)
            .await
            .map_err(BlockFetcherError::StoreError)
    }

    async fn get_logs(&mut self) -> Result<Vec<RpcLog>, BlockFetcherError> {
        let last_l1_block_number = self.eth_client.get_block_number().await?;

        let mut batch_committed_logs = Vec::new();
        while self.last_l1_block_fetched < last_l1_block_number {
            let new_last_l1_fetched_block = min(
                self.last_l1_block_fetched + self.max_block_step,
                last_l1_block_number,
            );

            debug!(
                "Fetching logs from block {} to {}",
                self.last_l1_block_fetched + 1,
                new_last_l1_fetched_block
            );

            // Fetch logs from the L1 chain for the BatchCommitted event.
            let logs = self
                .eth_client
                .get_logs(
                    self.last_l1_block_fetched + 1,
                    new_last_l1_fetched_block,
                    self.on_chain_proposer_address,
                    keccak(b"BatchCommitted(uint256,bytes32)"),
                )
                .await?;

            // Update the last L1 block fetched.
            self.last_l1_block_fetched = new_last_l1_fetched_block;

            batch_committed_logs.extend_from_slice(&logs);

            sleep(Duration::from_millis(self.fetch_interval_ms)).await;
        }

        Ok(batch_committed_logs)
    }

    async fn filter_logs(&self, logs: &[RpcLog]) -> Result<Vec<(RpcLog, U256)>, BlockFetcherError> {
        let mut filtered_logs = Vec::new();

        let last_block_number_known = self.store.get_latest_block_number().await?;

        let last_batch_number_known = self
            .rollup_store
            .get_batch_number_by_block(last_block_number_known)
            .await?
            .ok_or(BlockFetcherError::InternalError(format!(
                "Failed to get last batch number known for block {last_block_number_known}"
            )))?;

        // Filter missing batches logs
        for batch_committed_log in logs.iter().cloned() {
            let committed_batch_number = U256::from_big_endian(
                batch_committed_log
                    .log
                    .topics
                    .get(1)
                    .ok_or(BlockFetcherError::InternalError(
                        "Failed to get committed batch number from BatchCommitted log".to_string(),
                    ))?
                    .as_bytes(),
            );

            if committed_batch_number > last_batch_number_known.into() {
                filtered_logs.push((batch_committed_log, committed_batch_number));
            }
        }

        Ok(filtered_logs)
    }

    // TODO: Move to calldata module (SDK)
    fn decode_batch_from_calldata(calldata: &[u8]) -> Result<Vec<Block>, BlockFetcherError> {
        // function commitBatch(
        //     uint256 batchNumber,
        //     bytes32 newStateRoot,
        //     bytes32 stateDiffKZGVersionedHash,
        //     bytes32 withdrawalsLogsMerkleRoot,
        //     bytes32 processedDepositLogsRollingHash,
        //     bytes[] calldata _hexEncodedBlocks
        // ) external;

        // data =   4 bytes (function selector) 0..4
        //          || 8 bytes (batch number)   4..36
        //          || 32 bytes (new state root) 36..68
        //          || 32 bytes (state diff KZG versioned hash) 68..100
        //          || 32 bytes (withdrawals logs merkle root) 100..132
        //          || 32 bytes (processed deposit logs rolling hash) 132..164

        let batch_length_in_blocks = U256::from_big_endian(calldata.get(196..228).ok_or(
            BlockFetcherError::WrongBatchCalldata("Couldn't get batch length bytes".to_owned()),
        )?)
        .as_usize();

        let base = 228;

        let mut batch = Vec::new();

        for block_i in 0..batch_length_in_blocks {
            let block_length_offset = base + block_i * 32;

            let dynamic_offset = U256::from_big_endian(
                calldata
                    .get(block_length_offset..block_length_offset + 32)
                    .ok_or(BlockFetcherError::WrongBatchCalldata(
                        "Couldn't get dynamic offset bytes".to_owned(),
                    ))?,
            )
            .as_usize();

            let block_length_in_bytes = U256::from_big_endian(
                calldata
                    .get(base + dynamic_offset..base + dynamic_offset + 32)
                    .ok_or(BlockFetcherError::WrongBatchCalldata(
                        "Couldn't get block length bytes".to_owned(),
                    ))?,
            )
            .as_usize();

            let block_offset = base + dynamic_offset + 32;

            let block = Block::decode(
                calldata
                    .get(block_offset..block_offset + block_length_in_bytes)
                    .ok_or(BlockFetcherError::WrongBatchCalldata(
                        "Couldn't get block bytes".to_owned(),
                    ))?,
            )?;

            batch.push(block);
        }

        Ok(batch)
    }

    async fn store_batch(&self, batch: &[Block]) -> Result<(), BlockFetcherError> {
        for block in batch.iter() {
            self.blockchain.add_block(block).await?;

            let block_hash = block.hash();

            apply_fork_choice(&self.store, block_hash, block_hash, block_hash).await?;

            info!(
                "Added fetched block {} with hash {block_hash:#x}",
                block.header.number,
            );
        }

        Ok(())
    }

    async fn seal_batch(
        &self,
        batch: &[Block],
        batch_number: U256,
    ) -> Result<(), BlockFetcherError> {
        self.rollup_store
            .seal_batch(
                batch_number.as_u64(),
                batch
                    .first()
                    .ok_or(BlockFetcherError::InternalError(
                        "Batch is empty. This shouldn't happen.".to_owned(),
                    ))?
                    .header
                    .number,
                batch
                    .last()
                    .ok_or(BlockFetcherError::InternalError(
                        "Batch is empty. This shouldn't happen.".to_owned(),
                    ))?
                    .header
                    .number,
                self.get_batch_withdrawal_hashes(batch).await?,
            )
            .await?;

        info!("Sealed batch {batch_number}."); //. First block: {}, last block: {}",);

        Ok(())
    }

    async fn get_batch_withdrawal_hashes(
        &self,
        batch: &[Block],
    ) -> Result<Vec<H256>, BlockFetcherError> {
        let mut withdrawal_hashes = Vec::new();

        for block in batch {
            let block_withdrawals = self.get_block_withdrawals(block.header.number).await?;

            for (_tx_hash, tx) in &block_withdrawals {
                let hash = get_withdrawal_hash(tx).ok_or(BlockFetcherError::InternalError(
                    "Invalid withdraw transaction".to_owned(),
                ))?;
                withdrawal_hashes.push(hash);
            }
        }

        Ok(withdrawal_hashes)
    }

    async fn get_block_withdrawals(
        &self,
        block_number: BlockNumber,
    ) -> Result<Vec<(H256, Transaction)>, BlockFetcherError> {
        let Some(block_body) = self.store.get_block_body(block_number).await? else {
            return Err(BlockFetcherError::InternalError(format!(
                "Block {block_number} is supposed to be in store at this point"
            )));
        };

        let mut txs_and_receipts = vec![];
        for (index, tx) in block_body.transactions.iter().enumerate() {
            let receipt = self
                .store
                .get_receipt(
                    block_number,
                    index.try_into().map_err(|_| {
                        BlockFetcherError::InternalError(
                            "Failed to convert index to u64".to_owned(),
                        )
                    })?,
                )
                .await?
                .ok_or(BlockFetcherError::InternalError(
                    "Transactions in a block should have a receipt".to_owned(),
                ))?;
            txs_and_receipts.push((tx.clone(), receipt));
        }

        let mut ret = vec![];

        for (tx, receipt) in txs_and_receipts {
            if is_withdrawal_l2(&tx, &receipt)? {
                ret.push((tx.compute_hash(), tx.clone()))
            }
        }
        Ok(ret)
    }
}
