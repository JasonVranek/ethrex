mod bytecode_fetcher;
mod fetcher_queue;
mod state_healing;
mod state_sync;
mod storage_fetcher;
mod storage_healing;
mod trie_rebuild;

use bytecode_fetcher::bytecode_fetcher;
use ethrex_blockchain::{error::ChainError, BatchBlockProcessingFailure, Blockchain};
use ethrex_common::{
    types::{Block, BlockHash},
    BigEndianHash, H256, U256, U512,
};
use ethrex_rlp::error::RLPDecodeError;
use ethrex_storage::{error::StoreError, EngineType, Store, STATE_TRIE_SEGMENTS};
use ethrex_trie::{Nibbles, Node, TrieDB, TrieError};
use state_healing::heal_state_trie;
use state_sync::state_sync;
use std::{
    array,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};
use storage_healing::storage_healer;
use tokio::{
    sync::mpsc::error::SendError,
    time::{Duration, Instant},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use trie_rebuild::TrieRebuilder;

use crate::peer_handler::{BlockRequestOrder, PeerHandler, HASH_MAX};

/// The minimum amount of blocks from the head that we want to full sync during a snap sync
const MIN_FULL_BLOCKS: usize = 64;
/// Max size of bach to start a bytecode fetch request in queues
const BYTECODE_BATCH_SIZE: usize = 70;
/// Max size of a bach to start a storage fetch request in queues
const STORAGE_BATCH_SIZE: usize = 300;
/// Max size of a bach to start a node fetch request in queues
const NODE_BATCH_SIZE: usize = 900;
/// Maximum amount of concurrent paralell fetches for a queue
const MAX_PARALLEL_FETCHES: usize = 10;
/// Maximum amount of messages in a channel
const MAX_CHANNEL_MESSAGES: usize = 500;
/// Maximum amount of messages to read from a channel at once
const MAX_CHANNEL_READS: usize = 200;
/// Pace at which progress is shown via info tracing
const SHOW_PROGRESS_INTERVAL_DURATION: Duration = Duration::from_secs(30);
/// Amount of blocks to execute at once during full sync
/// In snap sync these blocks are stored without execution
const EXECUTE_BLOCK_BATCH: usize = 1024;

lazy_static::lazy_static! {
    // Size of each state trie segment
    static ref STATE_TRIE_SEGMENT_SIZE: U256 = HASH_MAX.into_uint()/STATE_TRIE_SEGMENTS;
    // Starting hash of each state trie segment
    static ref STATE_TRIE_SEGMENTS_START: [H256; STATE_TRIE_SEGMENTS] = {
        array::from_fn(|i| H256::from_uint(&(*STATE_TRIE_SEGMENT_SIZE * i)))
    };
    // Ending hash of each state trie segment
    static ref STATE_TRIE_SEGMENTS_END: [H256; STATE_TRIE_SEGMENTS] = {
        array::from_fn(|i| H256::from_uint(&(*STATE_TRIE_SEGMENT_SIZE * (i+1))))
    };
}

#[derive(Debug, PartialEq, Clone, Default)]
pub enum SyncMode {
    #[default]
    Full,
    Snap,
}

/// Manager in charge the sync process
/// Only performs full-sync but will also be in charge of snap-sync in the future
#[derive(Debug)]
pub struct Syncer {
    /// This is also held by the SyncManager allowing it to track the latest syncmode, without modifying it
    /// No outside process should modify this value, only being modified by the sync cycle
    snap_enabled: Arc<AtomicBool>,
    peers: PeerHandler,
    /// The last block number used as a pivot for snap-sync
    /// Syncing beyond this pivot should re-enable snap-sync (as we will not have that state stored)
    /// TODO: Reorgs
    last_snap_pivot: u64,
    trie_rebuilder: Option<TrieRebuilder>,
    // Used for cancelling long-living tasks upon shutdown
    cancel_token: CancellationToken,
    blockchain: Arc<Blockchain>,
}

impl Syncer {
    pub fn new(
        peers: PeerHandler,
        snap_enabled: Arc<AtomicBool>,
        cancel_token: CancellationToken,
        blockchain: Arc<Blockchain>,
    ) -> Self {
        Self {
            snap_enabled,
            peers,
            last_snap_pivot: 0,
            trie_rebuilder: None,
            cancel_token,
            blockchain,
        }
    }

    /// Creates a dummy Syncer for tests where syncing is not needed
    /// This should only be used in tests as it won't be able to connect to the p2p network
    pub fn dummy() -> Self {
        Self {
            snap_enabled: Arc::new(AtomicBool::new(false)),
            peers: PeerHandler::dummy(),
            last_snap_pivot: 0,
            trie_rebuilder: None,
            // This won't be used
            cancel_token: CancellationToken::new(),
            blockchain: Arc::new(Blockchain::default_with_store(
                Store::new("", EngineType::InMemory).unwrap(),
            )),
        }
    }

    /// Starts a sync cycle, updating the state with all blocks between the current head and the sync head
    /// Will perforn either full or snap sync depending on the manager's `snap_mode`
    /// In full mode, all blocks will be fetched via p2p eth requests and executed to rebuild the state
    /// In snap mode, blocks and receipts will be fetched and stored in parallel while the state is fetched via p2p snap requests
    /// After the sync cycle is complete, the sync mode will be set to full
    /// If the sync fails, no error will be returned but a warning will be emitted
    /// [WARNING] Sync is done optimistically, so headers and bodies may be stored even if their data has not been fully synced if the sync is aborted halfway
    /// [WARNING] Sync is currenlty simplified and will not download bodies + receipts previous to the pivot during snap sync
    pub async fn start_sync(&mut self, current_head: H256, sync_head: H256, store: Store) {
        info!(
            "Syncing from current head {:?} to sync_head {:?}",
            current_head, sync_head
        );
        let start_time = Instant::now();
        match self.sync_cycle(current_head, sync_head, store).await {
            Ok(()) => {
                info!(
                    "Sync cycle finished, time elapsed: {} secs",
                    start_time.elapsed().as_secs()
                );
            }
            Err(error) => warn!(
                "Sync cycle failed due to {error}, time elapsed: {} secs ",
                start_time.elapsed().as_secs()
            ),
        }
    }

    /// Performs the sync cycle described in `start_sync`, returns an error if the sync fails at any given step and aborts all active processes
    async fn sync_cycle(
        &mut self,
        current_head: H256,
        sync_head: H256,
        store: Store,
    ) -> Result<(), SyncError> {
        // Spawn the continuous sync process
        // This will be in charge of downloading all blocks and either:
        // FullSync: Executing and storing them
        // SnapSync: Storing them and downloading their receipts
        let ongoing_sync_cancel = self.cancel_token.child_token();
        let continuous_sync = tokio::task::spawn(Self::ongoing_sync(
            self.snap_enabled.clone(),
            self.peers.clone(),
            current_head,
            sync_head,
            self.blockchain.clone(),
            store.clone(),
            ongoing_sync_cancel.clone(),
        ));
        // Meanwhile if snap sync is enabled, go through as many snap sync cycles as we need to
        if self.snap_enabled.load(Ordering::Relaxed) {
            let block_after_snap = if let Some((pivot_root, next_block_hash)) =
                self.find_snap_pivot(sync_head, store.clone()).await?
            {
                self.snap_sync(pivot_root, store.clone())
                    .await?
                    .then_some(next_block_hash)
            } else {
                None
            };
            if let Some(next_block) = block_after_snap {
                continuous_sync.await??;
                self.finalize_snap_sync(store, next_block).await
            } else {
                ongoing_sync_cancel.cancel();
                continuous_sync.await?
            }
        } else {
            continuous_sync.await?
        }
    }

    /// Performs the sync cycle described in `start_sync`, returns an error if the sync fails at any given step and aborts all active processes
    async fn ongoing_sync(
        snap_enabled: Arc<AtomicBool>,
        peers: PeerHandler,
        mut current_head: H256,
        sync_head: H256,
        blockchain: Arc<Blockchain>,
        store: Store,
        cancel_token: CancellationToken,
    ) -> Result<(), SyncError> {
        // Take picture of the current sync mode, we will update the original value when we need to
        let mut sync_mode = if snap_enabled.load(Ordering::Relaxed) {
            SyncMode::Snap
        } else {
            SyncMode::Full
        };
        // Check if we have some blocks downloaded from a previous sync attempt
        // This applies only to snap sync, full sync always starts fetching headers
        // from the canonical block, which updates as new block headers are fetched.
        if matches!(sync_mode, SyncMode::Snap) {
            if let Some(last_header) = store.get_header_download_checkpoint().await? {
                // Set latest downloaded header as current head for header fetching
                current_head = last_header;
            }
        }

        let pending_block = match store.get_pending_block(sync_head).await {
            Ok(res) => res,
            Err(e) => return Err(e.into()),
        };

        // Current un-processed block headers and bodies
        // Aka the ones we have downloaded from peers but are yet to execute/store
        let mut current_headers = Vec::new();
        let mut current_blocks = Vec::new();

        // TODO(#2126): To avoid modifying the current_head while backtracking we use a separate search_head
        let mut search_head = current_head;

        loop {
            if cancel_token.is_cancelled() {
                break;
            }
            let since = Instant::now();
            debug!("Requesting Block Headers from {search_head}");

            let Some(mut block_headers) = peers
                .request_block_headers(search_head, BlockRequestOrder::OldToNew)
                .await
            else {
                warn!("Sync failed to find target block header, aborting");
                return Ok(());
            };

            let mut block_hashes: Vec<BlockHash> =
                block_headers.iter().map(|header| header.hash()).collect();

            // Empty batches are not valid so these are guaranteed to exist
            let first_block_header = block_headers.first().unwrap().clone();
            let last_block_header = block_headers.last().unwrap().clone();
            // TODO(#2126): This is just a temporary solution to avoid a bug where the sync would get stuck
            // on a loop when the target head is not found, i.e. on a reorg with a side-chain.
            if first_block_header == last_block_header
                && first_block_header.hash() == search_head
                && search_head != sync_head
            {
                // There is no path to the sync head this goes back until it find a common ancerstor
                warn!("Sync failed to find target block header, going back to the previous parent");
                search_head = first_block_header.parent_hash;
                continue;
            }

            debug!(
                "Received {} block headers| First Number: {} Last Number: {}",
                block_headers.len(),
                first_block_header.number,
                last_block_header.number
            );

            // If we have a pending block from new_payload request
            // attach it to the end if it matches the parent_hash of the latest received header
            if let Some(ref block) = pending_block {
                if block.header.parent_hash == last_block_header.hash() {
                    block_hashes.push(block.hash());
                    block_headers.push(block.header.clone());
                }
            }

            // Filter out everything after the sync_head
            let mut sync_head_found = false;
            if let Some(index) = block_hashes.iter().position(|&hash| hash == sync_head) {
                sync_head_found = true;
                block_hashes = block_hashes.iter().take(index + 1).cloned().collect();
            }

            // Update current fetch head if needed
            let last_block_hash = last_block_header.hash();
            if !sync_head_found {
                debug!(
                    "Syncing head not found, updated current_head {:?}",
                    last_block_hash
                );
                search_head = last_block_hash;
                current_head = last_block_hash;
                if sync_mode == SyncMode::Snap {
                    store.set_header_download_checkpoint(current_head).await?;
                }
            }

            // If the sync head is less than 64 blocks away from our current head switch to full-sync
            if sync_mode == SyncMode::Snap {
                let latest_block_number = store.get_latest_block_number().await?;
                if last_block_header.number.saturating_sub(latest_block_number)
                    < MIN_FULL_BLOCKS as u64
                {
                    // Too few blocks for a snap sync, switching to full sync
                    store.clear_snap_state().await?;
                    sync_mode = SyncMode::Full;
                    snap_enabled.store(false, Ordering::Relaxed);
                }
            }

            // Discard the first header as we already have it
            block_hashes.remove(0);
            block_headers.remove(0);

            // Add block_headers to our current block_headers
            current_headers.extend(block_headers);


            // If we don't have enough headers to process a batch of blocks, fetch more
            if current_headers.len() < EXECUTE_BLOCK_BATCH && !sync_head_found {
                // Fetch more headers
                continue;
            }

            // If we don't have enough full blocks to process a batch of blocks, fetch more
            while current_blocks.len() < EXECUTE_BLOCK_BATCH && !current_headers.is_empty() {
                if cancel_token.is_cancelled() {
                    break;
                }
                // Download block bodies
                info!("Requesting Block Bodies, available headers: {}", current_headers.len());
                let mut current_hashes = current_headers.iter().map(|h| h.hash()).collect();
                let blocks = peers
                    .request_and_validate_block_bodies(&mut current_hashes, &mut current_headers)
                    .await
                    .ok_or(SyncError::BodiesNotFound)?;
                dbg!("Obtained: {} blocks", blocks.len());
                current_blocks.extend(blocks);
            }

            info!("Block batch ready to execute/store");
            while current_blocks.len() > EXECUTE_BLOCK_BATCH || (current_blocks.len() > 0 && sync_head_found) {
            // Now that we have a full batch, we will either
            // - Full Sync: Execute & store them
            // - Snap Sync: Store them & Fetch their Receipts (TODO)
            let block_batch: Vec<Block> = current_blocks.drain(..EXECUTE_BLOCK_BATCH).collect();
            match sync_mode {
                SyncMode::Full => {
                    // Copy some values for later
                    let last_block = block_batch.last().cloned().unwrap();
                    let first_block = block_batch.first().cloned().unwrap();
                    let blocks_len = block_batch.len();
                    // Spawn a blocking task to not block the tokio runtime
                    // If we found the sync head, run the blocks sequentially to store all the blocks's state
                    if let Err((err, batch_failure)) =
                        Self::add_blocks(blockchain.clone(), block_batch, sync_head_found).await
                    {
                        if let Some(batch_failure) = batch_failure {
                            warn!("Failed to add block during FullSync: {err}");
                            store
                                .set_latest_valid_ancestor(
                                    batch_failure.failed_block_hash,
                                    batch_failure.last_valid_hash,
                                )
                                .await?;
                            // TODO(#2127): Just marking the failing ancestor and the sync head is enough
                            // to fix the Missing Ancestors hive test, we want to look at a more robust
                            // solution in the future if needed.
                            store
                                .set_latest_valid_ancestor(sync_head, batch_failure.last_valid_hash)
                                .await?;
                        }
                        return Err(err.into());
                    }

                    store
                        .update_latest_block_number(last_block.header.number)
                        .await?;

                    let elapsed_secs: f64 = since.elapsed().as_millis() as f64 / 1000.0;
                    let blocks_per_second = blocks_len as f64 / elapsed_secs;

                    info!(
                        "[SYNCING] Requested, stored, and executed {} blocks in {:.3} seconds.\n\
            Started at block with hash {} (number {}).\n\
            Finished at block with hash {} (number {}).\n\
            Blocks per second: {:.3}",
                        blocks_len,
                        elapsed_secs,
                        first_block.hash(),
                        first_block.header.number,
                        last_block.hash(),
                        last_block.header.number,
                        blocks_per_second
                    );
                }
                SyncMode::Snap => store.add_blocks(block_batch).await?,
            }
        }

            if sync_head_found {
                break;
            };
        }
        Ok(())
    }

    async fn add_blocks(
        blockchain: Arc<Blockchain>,
        blocks: Vec<Block>,
        sync_head_found: bool,
    ) -> Result<(), (ChainError, Option<BatchBlockProcessingFailure>)> {
        // If we found the sync head, run the blocks sequentially to store all the blocks's state
        if sync_head_found {
            let mut last_valid_hash = H256::default();
            for block in blocks {
                blockchain.add_block(&block).await.map_err(|e| {
                    (
                        e,
                        Some(BatchBlockProcessingFailure {
                            last_valid_hash,
                            failed_block_hash: block.hash(),
                        }),
                    )
                })?;
                last_valid_hash = block.hash();
            }
            Ok(())
        } else {
            blockchain.add_blocks_in_batch(blocks).await
        }
    }
}

/// Fetches all receipts for the given block hashes via p2p and stores them
// TODO: remove allow when used again
#[allow(unused)]
async fn store_receipts(
    mut block_hashes: Vec<BlockHash>,
    peers: PeerHandler,
    store: Store,
) -> Result<(), SyncError> {
    loop {
        debug!("Requesting Receipts ");
        if let Some(receipts) = peers.request_receipts(block_hashes.clone()).await {
            debug!(" Received {} Receipts", receipts.len());
            // Track which blocks we have already fetched receipts for
            for (block_hash, receipts) in block_hashes.drain(0..receipts.len()).zip(receipts) {
                store.add_receipts(block_hash, receipts).await?;
            }
            // Check if we need to ask for another batch
            if block_hashes.is_empty() {
                break;
            }
        }
    }
    Ok(())
}

impl Syncer {
    /// Performs the sync cycle described in `start_sync`, returns an error if the sync fails at any given step and aborts all active processes
    async fn find_snap_pivot(
        &mut self,
        sync_head: H256,
        store: Store,
    ) -> Result<Option<(H256, H256)>, SyncError> {
        // Fetch only the block header batch containing the sync_head
        debug!("Requesting Block Headers from {sync_head}");
        let Some(block_headers) = self
            .peers
            .request_block_headers(sync_head, BlockRequestOrder::NewToOld)
            .await
        else {
            warn!("Sync failed to find target block header, aborting");
            return Ok(None);
        };

        let block_hashes: Vec<BlockHash> =
            block_headers.iter().map(|header| header.hash()).collect();

        // Check that the peer response does contain our sync_head
        let Some(sync_head_index) = block_hashes.iter().position(|h| h == &sync_head) else {
            warn!("Sync failed to find target block header, invalid response from peers");
            return Ok(None);
        };
        // If the sync head is less than 64 blocks away from our current head switch to full-sync
        let latest_block_number = store.get_latest_block_number().await?;
        if block_headers[sync_head_index]
            .number
            .saturating_sub(latest_block_number)
            < MIN_FULL_BLOCKS as u64
        {
            // Too few blocks for a snap sync, switching to full sync
            store.clear_snap_state().await?;

            self.snap_enabled.store(false, Ordering::Relaxed);
        }

        // snap-sync: launch tasks to fetch blocks and state in parallel
        // - Fetch each block's body and its receipt via eth p2p requests
        // - Fetch the pivot block's state via snap p2p requests
        // - Execute blocks after the pivot (like in full-sync)
        let pivot_idx = block_hashes.len().saturating_sub(MIN_FULL_BLOCKS);
        let pivot_header = &block_headers[pivot_idx];

        debug!(
            "Selected block {} as pivot for snap sync",
            pivot_header.number
        );

        // Return the pivot's state_root and the block_hash of the block after the pivot
        Ok(Some((pivot_header.state_root, block_hashes[pivot_idx + 1])))
    }

    /// Execute the next block after a succesful snap sync cycle, set it as canonical & change sync_mode to full
    /// Should only be called after all blocks have been downloaded
    async fn finalize_snap_sync(
        &mut self,
        store: Store,
        block_after_pivot: H256,
    ) -> Result<(), SyncError> {
        let block = store
            .get_block_by_hash(block_after_pivot)
            .await?
            .ok_or(SyncError::CorruptDB)?;
        let block_number = block.header.number;
        self.blockchain.add_block(&block).await?;
        store
            .set_canonical_block(block_number, block_after_pivot)
            .await?;
        store.update_latest_block_number(block_number).await?;
        self.last_snap_pivot = block_number - 1;
        // Finished a sync cycle without aborting halfway, clear current checkpoint
        store.clear_snap_state().await?;
        // Next sync will be full-sync
        self.snap_enabled.store(false, Ordering::Relaxed);
        Ok(())
    }
    /// Downloads the latest state trie and all associated storage tries & bytecodes from peers
    /// Rebuilds the state trie and all storage tries based on the downloaded data
    /// Performs state healing in order to fix all inconsistencies with the downloaded state
    /// Returns the success status, if it is true, then the state is fully consistent and
    /// new blocks can be executed on top of it, if false then the state is still inconsistent and
    /// snap sync must be resumed on the next sync cycle
    async fn snap_sync(&mut self, state_root: H256, store: Store) -> Result<bool, SyncError> {
        // Begin the background trie rebuild process if it is not active yet or if it crashed
        if !self
            .trie_rebuilder
            .as_ref()
            .is_some_and(|rebuilder| rebuilder.alive())
        {
            self.trie_rebuilder = Some(TrieRebuilder::startup(
                self.cancel_token.clone(),
                store.clone(),
            ));
        };
        // Spawn storage healer earlier so we can start healing stale storages
        // Create a cancellation token so we can end the storage healer when finished, make it a child so that it also ends upon shutdown
        let storage_healer_cancell_token = self.cancel_token.child_token();
        // Create an AtomicBool to signal to the storage healer whether state healing has ended
        let state_healing_ended = Arc::new(AtomicBool::new(false));
        let storage_healer_handler = tokio::spawn(storage_healer(
            state_root,
            self.peers.clone(),
            store.clone(),
            storage_healer_cancell_token.clone(),
            state_healing_ended.clone(),
        ));
        // Perform state sync if it was not already completed on a previous cycle
        // Retrieve storage data to check which snap sync phase we are in
        let key_checkpoints = store.get_state_trie_key_checkpoint().await?;
        // If we have no key checkpoints or if the key checkpoints are lower than the segment boundaries we are in state sync phase
        if key_checkpoints.is_none()
            || key_checkpoints.is_some_and(|ch| {
                ch.into_iter()
                    .zip(STATE_TRIE_SEGMENTS_END.into_iter())
                    .any(|(ch, end)| ch < end)
            })
        {
            let stale_pivot = state_sync(
                state_root,
                store.clone(),
                self.peers.clone(),
                key_checkpoints,
                self.trie_rebuilder
                    .as_ref()
                    .unwrap()
                    .storage_rebuilder_sender
                    .clone(),
            )
            .await?;
            if stale_pivot {
                warn!("Stale Pivot, aborting state sync");
                storage_healer_cancell_token.cancel();
                storage_healer_handler.await??;
                return Ok(false);
            }
        }
        // Wait for the trie rebuilder to finish
        info!("Waiting for the trie rebuild to finish");
        let rebuild_start = Instant::now();
        self.trie_rebuilder.take().unwrap().complete().await?;
        info!(
            "State trie rebuilt from snapshot, overtime: {}",
            rebuild_start.elapsed().as_secs()
        );
        // Clear snapshot
        store.clear_snapshot().await?;

        // Perform Healing
        let state_heal_complete =
            heal_state_trie(state_root, store.clone(), self.peers.clone()).await?;
        // Wait for storage healer to end
        if state_heal_complete {
            state_healing_ended.store(true, Ordering::Relaxed);
        } else {
            storage_healer_cancell_token.cancel();
        }
        let storage_heal_complete = storage_healer_handler.await??;
        if !(state_heal_complete && storage_heal_complete) {
            warn!("Stale pivot, aborting healing");
        }
        Ok(state_heal_complete && storage_heal_complete)
    }
}

/// Returns the partial paths to the node's children if they are not already part of the trie state
fn node_missing_children(
    node: &Node,
    parent_path: &Nibbles,
    trie_state: &dyn TrieDB,
) -> Result<Vec<Nibbles>, TrieError> {
    let mut paths = Vec::new();
    match &node {
        Node::Branch(node) => {
            for (index, child) in node.choices.iter().enumerate() {
                if child.is_valid() && child.get_node(trie_state)?.is_none() {
                    paths.push(parent_path.append_new(index as u8));
                }
            }
        }
        Node::Extension(node) => {
            if node.child.is_valid() && node.child.get_node(trie_state)?.is_none() {
                paths.push(parent_path.concat(node.prefix.clone()));
            }
        }
        _ => {}
    }
    Ok(paths)
}

fn seconds_to_readable(seconds: U512) -> String {
    let (days, rest) = seconds.div_mod(U512::from(60 * 60 * 24));
    let (hours, rest) = rest.div_mod(U512::from(60 * 60));
    let (minutes, seconds) = rest.div_mod(U512::from(60));
    if days > U512::zero() {
        if days > U512::from(15) {
            return "unknown".to_string();
        }
        return format!("Over {days} days");
    }
    format!("{hours}h{minutes}m{seconds}s")
}

#[derive(thiserror::Error, Debug)]
enum SyncError {
    #[error(transparent)]
    Chain(#[from] ChainError),
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error("{0}")]
    Send(String),
    #[error(transparent)]
    Trie(#[from] TrieError),
    #[error(transparent)]
    Rlp(#[from] RLPDecodeError),
    #[error("Corrupt path during state healing")]
    CorruptPath,
    #[error(transparent)]
    JoinHandle(#[from] tokio::task::JoinError),
    #[error("Missing data from DB")]
    CorruptDB,
    #[error("No bodies were found for the given headers")]
    BodiesNotFound,
}

impl<T> From<SendError<T>> for SyncError {
    fn from(value: SendError<T>) -> Self {
        Self::Send(value.to_string())
    }
}
