//! This module contains the logic for the state sync process
//! This process will begin as soon as headers are downloaded and a pivot block is selected
//! It consist of separating the state trie into `STATE_TRIE_SEGMENTS` number of segments and downloading each state trie segment in parallel
//! The data downloaded consist of plain accounts from the leaves of the current cannonical state trie
//! Each account will be written to the state snapshot in the DB which will later be used by the trie rebuild process
//! Each account's bytecode & storage will also be downloaded by the corresponding processes

use std::sync::Arc;

use ethrex_common::{BigEndianHash, H256, U256, U512, constants::EMPTY_KECCACK_HASH, types::batch};
use ethrex_storage::{STATE_TRIE_SEGMENTS, Store};
use ethrex_trie::EMPTY_TRIE_HASH;
use tokio::{
    sync::{
        Mutex,
        mpsc::{Sender, channel},
    },
    time::{Instant, sleep},
};
use tracing::{debug, info, warn};

use crate::{
    peer_handler::PeerHandler,
    sync::{
        BYTECODE_BATCH_SIZE, MAX_CHANNEL_MESSAGES, STATE_TRIE_SEGMENTS_END,
        STATE_TRIE_SEGMENTS_START, STORAGE_BATCH_SIZE, bytecode_fetcher, seconds_to_readable,
        storage_fetcher::storage_fetcher,
    },
};

use super::{SHOW_PROGRESS_INTERVAL_DURATION, SyncError};

fn increase_hash_by_one(hash: &H256) -> H256 {
    let next_hash_uint = U256::from_big_endian(&hash.0).saturating_add(U256::one());
    H256::from_uint(&next_hash_uint)
}

pub(crate) async fn state_sync(
    state_root: H256,
    store: Store,
    peers: PeerHandler,
    range_start: H256,
) -> Result<(bool, H256), SyncError> {
    info!("Starting state sync phase, fetching accounts...");
    let start = Instant::now();
    let mut n_accounts = 0;

    let mut start_account_hash = range_start;
    let end_account_hash = H256::repeat_byte(0xff);
    let mut stale = false;
    'outer: loop {
        info!(
            "Requesting accounts in range [{}, {}]",
            start_account_hash, end_account_hash
        );
        // Request accounts
        let Some((account_hashes, accounts, should_continue)) = peers
            .request_account_range(state_root, start_account_hash, end_account_hash)
            .await
        else {
            warn!("Failed to fetch accounts in range. State might be too old.");
            stale = true;
            break;
        };

        if account_hashes.is_empty() {
            warn!("Got no accounts");
            continue;
        }
        n_accounts += account_hashes.len();

        info!(
            "Received {} accounts in range [{}, {}]",
            account_hashes.len(),
            start_account_hash,
            end_account_hash
        );

        let next_start = *account_hashes
            .last()
            .expect("we already checked this is not empty");

        // Store the accounts in DB
        store
            .write_snapshot_account_batch(account_hashes.clone(), accounts.clone())
            .await?;

        // Fetch Account Storage & Bytecode
        let mut code_hashes = vec![];
        let mut account_hashes_and_storage_roots = vec![];
        for (account_hash, account) in account_hashes.iter().zip(accounts.iter()) {
            // Ignore accounts without code / code we already have stored
            // PERF: going to the DB here might be slow?
            if account.code_hash != *EMPTY_KECCACK_HASH
                && store.get_account_code(account.code_hash)?.is_none()
            {
                code_hashes.push(account.code_hash)
            }
            // Ignore accounts without storage and account's which storage hasn't changed from our current stored state
            if account.storage_root != *EMPTY_TRIE_HASH
                && !store.contains_storage_node(*account_hash, account.storage_root)?
            {
                account_hashes_and_storage_roots.push((*account_hash, account.storage_root));
            }
        }

        info!(
            "Downloading storage tries for {} accounts",
            account_hashes_and_storage_roots.len()
        );

        // Fetch storage tries
        let mut last_storage_key = H256::zero();
        while account_hashes_and_storage_roots.len() > 0 {
            // We got to a "big storage" account, so we need to request storage only for it
            let batch = if !last_storage_key.is_zero() {
                let last_account = account_hashes_and_storage_roots
                    .last()
                    .expect("can't be empty");
                vec![last_account.clone()]
            } else {
                account_hashes_and_storage_roots
                    .iter()
                    .take(STORAGE_BATCH_SIZE)
                    .cloned()
                    .collect::<Vec<_>>()
            };
            let (mut account_hashes, mut storage_roots): (Vec<_>, Vec<_>) =
                batch.iter().cloned().unzip();

            let Some((storage_keys, storage_values, should_continue)) = peers
                .request_storage_ranges(
                    state_root,
                    storage_roots.clone(),
                    account_hashes.clone(),
                    last_storage_key,
                )
                .await
            else {
                warn!("Got no storages");
                break 'outer;
            };

            // TODO: this probably should be fixed at the peer handler level
            if storage_keys.is_empty() {
                info!("Got no storage keys");
                continue;
            }

            // Store downloaded storage range for each account
            for (account_hash, (keys, values)) in account_hashes
                .iter()
                .zip(storage_keys.iter().zip(storage_values.iter()))
            {
                store
                    .write_snapshot_storage_batch(*account_hash, keys.to_vec(), values.to_vec())
                    .await?;
            }

            // Remove the processed account hashes and storage roots
            let mut processed_count = storage_keys.len();
            if should_continue {
                processed_count -= 1; // Don't include the last account that we are still processing
                let last_key = storage_keys
                    .last()
                    .and_then(|hv| hv.last().copied())
                    .unwrap_or(H256::zero());

                last_storage_key = increase_hash_by_one(&last_key);
            } else {
                last_storage_key = H256::zero();
            }
            account_hashes.drain(..processed_count);
            storage_roots.drain(..processed_count);
        }

        info!("Downloading bytecode for {} accounts", code_hashes.len());

        let mut current_batch = vec![];
        // Fetch bytecodes
        for batch in code_hashes.chunks(BYTECODE_BATCH_SIZE) {
            current_batch.extend_from_slice(batch);
            loop {
                let Some(bytecode_batch) = peers.request_bytecodes(&current_batch).await else {
                    continue;
                };
                // Store the bytecodes
                // TODO: verify the code hash matches
                let code_hashes = current_batch.drain(..bytecode_batch.len());
                for (code_hash, code) in code_hashes.into_iter().zip(bytecode_batch) {
                    store.add_account_code(code_hash, code).await?;
                }
                if current_batch.is_empty() {
                    break;
                }
            }
        }

        // Start the next range from the last account hash + 1
        start_account_hash = increase_hash_by_one(&next_start);

        if !should_continue {
            start_account_hash = end_account_hash;
            break;
        }
    }

    let elapsed = start.elapsed();
    info!("Received {n_accounts} accounts accounts in {elapsed:?} seconds");

    Ok((stale, start_account_hash))
}

/// Downloads the leaf values of a Block's state trie by requesting snap state from peers
/// Also downloads the storage tries & bytecodes for each downloaded account
/// Receives optional checkpoints in case there was a previous snap sync process that became stale, in which
/// case it will resume it
/// Returns the pivot staleness status (true if stale, false if not)
/// If the pivot is not stale by the end of the state sync then the state sync was completed succesfuly
pub(crate) async fn state_sync_old(
    state_root: H256,
    store: Store,
    peers: PeerHandler,
    key_checkpoints: Option<[H256; STATE_TRIE_SEGMENTS]>,
    storage_trie_rebuilder_sender: Sender<Vec<(H256, H256)>>,
) -> Result<bool, SyncError> {
    // Spawn tasks to fetch each state trie segment
    let mut state_trie_tasks = tokio::task::JoinSet::new();
    // Spawn a task to show the state sync progress
    let state_sync_progress = StateSyncProgress::new(Instant::now());
    let show_progress_handle =
        tokio::task::spawn(show_state_sync_progress(state_sync_progress.clone()));
    for i in 0..STATE_TRIE_SEGMENTS {
        state_trie_tasks.spawn(state_sync_segment(
            state_root,
            peers.clone(),
            store.clone(),
            i,
            key_checkpoints.map(|chs| chs[i]),
            state_sync_progress.clone(),
            storage_trie_rebuilder_sender.clone(),
        ));
    }
    show_progress_handle.await?;
    // Check for pivot staleness
    let mut stale_pivot = false;
    let mut state_trie_checkpoint = [H256::zero(); STATE_TRIE_SEGMENTS];
    for res in state_trie_tasks.join_all().await {
        let (index, is_stale, last_key) = res?;
        stale_pivot |= is_stale;
        state_trie_checkpoint[index] = last_key;
    }
    // Update state trie checkpoint
    store
        .set_state_trie_key_checkpoint(state_trie_checkpoint)
        .await?;
    Ok(stale_pivot)
}

/// Downloads the leaf values of the given state trie segment by requesting snap state from peers
/// Also downloads the storage tries & bytecodes for each downloaded account
/// Receives an optional checkpoint from a previous state sync to resume it
/// Returns the segment number, the pivot staleness status (true if stale, false if not), and the last downloaded key
/// If the pivot is not stale by the end of the state sync then the state sync was completed succesfuly
#[allow(clippy::too_many_arguments)]
async fn state_sync_segment(
    state_root: H256,
    peers: PeerHandler,
    store: Store,
    segment_number: usize,
    checkpoint: Option<H256>,
    state_sync_progress: StateSyncProgress,
    storage_trie_rebuilder_sender: Sender<Vec<(H256, H256)>>,
) -> Result<(usize, bool, H256), SyncError> {
    // Resume download from checkpoint if available or start from an empty trie
    let mut start_account_hash = checkpoint.unwrap_or(STATE_TRIE_SEGMENTS_START[segment_number]);
    // Write initial sync progress (this task is not vital so we can detach it)
    tokio::task::spawn(StateSyncProgress::init_segment(
        state_sync_progress.clone(),
        segment_number,
        start_account_hash,
    ));
    // Skip state sync if we are already on healing
    if start_account_hash == STATE_TRIE_SEGMENTS_END[segment_number] {
        // Update sync progress (this task is not vital so we can detach it)
        tokio::task::spawn(StateSyncProgress::end_segment(
            state_sync_progress.clone(),
            segment_number,
            start_account_hash,
        ));
        return Ok((segment_number, false, start_account_hash));
    }
    // Spawn storage & bytecode fetchers
    let (bytecode_sender, bytecode_receiver) = channel::<Vec<H256>>(MAX_CHANNEL_MESSAGES);
    let (storage_sender, storage_receiver) = channel::<Vec<(H256, H256)>>(MAX_CHANNEL_MESSAGES);
    let bytecode_fetcher_handle = tokio::spawn(bytecode_fetcher(
        bytecode_receiver,
        peers.clone(),
        store.clone(),
    ));
    let storage_fetcher_handle = tokio::spawn(storage_fetcher(
        storage_receiver,
        peers.clone(),
        store.clone(),
        state_root,
        storage_trie_rebuilder_sender.clone(),
    ));
    info!(
        "Starting/Resuming state trie download of segment number {segment_number} from key {start_account_hash}"
    );
    // Fetch Account Ranges
    // If we reached the maximum amount of retries then it means the state we are requesting is probably old and no longer available
    let mut stale = false;
    loop {
        // Update sync progress (this task is not vital so we can detach it)
        tokio::task::spawn(StateSyncProgress::update_key(
            state_sync_progress.clone(),
            segment_number,
            start_account_hash,
        ));
        info!(
            "[Segment {segment_number}]: Requesting Account Range for state root {state_root}, starting hash: {start_account_hash}"
        );
        if let Some((account_hashes, accounts, should_continue)) = peers
            .request_account_range(
                state_root,
                start_account_hash,
                STATE_TRIE_SEGMENTS_END[segment_number],
            )
            .await
        {
            info!(
                "[Segment {segment_number}]: Received {} account ranges",
                accounts.len()
            );
            // Update starting hash for next batch
            let last_account_hash = account_hashes
                .last()
                .ok_or(SyncError::InvalidRangeReceived)?;
            start_account_hash = *last_account_hash;

            // Fetch Account Storage & Bytecode
            let mut code_hashes = vec![];
            let mut account_hashes_and_storage_roots = vec![];
            for (account_hash, account) in account_hashes.iter().zip(accounts.iter()) {
                // Build the batch of code hashes to send to the bytecode fetcher
                // Ignore accounts without code / code we already have stored
                if account.code_hash != *EMPTY_KECCACK_HASH
                    && store.get_account_code(account.code_hash)?.is_none()
                {
                    code_hashes.push(account.code_hash)
                }
                // Build the batch of hashes and roots to send to the storage fetcher
                // Ignore accounts without storage and account's which storage hasn't changed from our current stored state
                if account.storage_root != *EMPTY_TRIE_HASH
                    && !store.contains_storage_node(*account_hash, account.storage_root)?
                {
                    account_hashes_and_storage_roots.push((*account_hash, account.storage_root));
                }
            }
            // Send code hash batch to the bytecode fetcher
            if !code_hashes.is_empty() {
                bytecode_sender.send(code_hashes).await?;
            }
            // Send hash and root batch to the storage fetcher
            if !account_hashes_and_storage_roots.is_empty() {
                storage_sender
                    .send(account_hashes_and_storage_roots)
                    .await?;
            }
            // Update Snapshot
            store
                .write_snapshot_account_batch(account_hashes, accounts)
                .await?;
            // As we are downloading the state trie in segments the `should_continue` flag will mean that there
            // are more accounts to be fetched but these accounts may belong to the next segment
            if !should_continue || start_account_hash >= STATE_TRIE_SEGMENTS_END[segment_number] {
                // All accounts fetched!
                break;
            }
        } else {
            stale = true;
            break;
        }
    }
    debug!(
        "[Segment {segment_number}]: Account Trie Fetching ended, signaling storage & bytecode fetcher process"
    );
    // Update sync progress (this task is not vital so we can detach it)
    tokio::task::spawn(StateSyncProgress::end_segment(
        state_sync_progress.clone(),
        segment_number,
        start_account_hash,
    ));
    // Send empty batch to signal that no more batches are incoming
    storage_sender.send(vec![]).await?;
    bytecode_sender.send(vec![]).await?;
    storage_fetcher_handle.await??;
    bytecode_fetcher_handle.await??;
    if !stale {
        // State sync finished before becoming stale, update checkpoint so we skip state sync on the next cycle
        start_account_hash = STATE_TRIE_SEGMENTS_END[segment_number]
    }
    Ok((segment_number, stale, start_account_hash))
}

#[derive(Clone)]
struct StateSyncProgress {
    data: Arc<Mutex<StateSyncProgressData>>,
}

#[derive(Clone)]
struct StateSyncProgressData {
    cycle_start: Instant,
    initial_keys: [H256; STATE_TRIE_SEGMENTS],
    current_keys: [H256; STATE_TRIE_SEGMENTS],
    ended: [bool; STATE_TRIE_SEGMENTS],
}

impl StateSyncProgress {
    fn new(cycle_start: Instant) -> Self {
        Self {
            data: Arc::new(Mutex::new(StateSyncProgressData {
                cycle_start,
                initial_keys: Default::default(),
                current_keys: Default::default(),
                ended: Default::default(),
            })),
        }
    }

    async fn init_segment(progress: StateSyncProgress, segment_number: usize, initial_key: H256) {
        progress.data.lock().await.initial_keys[segment_number] = initial_key;
    }
    async fn update_key(progress: StateSyncProgress, segment_number: usize, current_key: H256) {
        progress.data.lock().await.current_keys[segment_number] = current_key
    }
    async fn end_segment(progress: StateSyncProgress, segment_number: usize, last_key: H256) {
        let mut data = progress.data.lock().await;
        data.ended[segment_number] = true;
        data.current_keys[segment_number] = last_key;
    }

    // Returns true if the state sync ended
    async fn show_progress(&self) -> bool {
        // Copy the current data so we don't read while it is being written
        let data = self.data.lock().await.clone();
        // Calculate the total amount of accounts synced
        let mut synced_accounts = U512::zero();
        // Calculate the total amount of accounts synced this cycle
        let mut synced_accounts_this_cycle = U512::one();
        for i in 0..STATE_TRIE_SEGMENTS {
            let segment_synced_accounts = U512::from(
                data.current_keys[i]
                    .into_uint()
                    .saturating_sub(STATE_TRIE_SEGMENTS_START[i].into_uint()),
            );
            let segment_completion_rate =
                ((segment_synced_accounts + 1) * 100) / U512::from(U256::MAX / STATE_TRIE_SEGMENTS);
            debug!("Segment {i} completion rate: {segment_completion_rate}%");
            synced_accounts += segment_synced_accounts;
            synced_accounts_this_cycle += data.current_keys[i]
                .into_uint()
                .saturating_sub(data.initial_keys[i].into_uint())
                .into();
        }
        // Calculate current progress percentage
        let completion_rate: U512 = (synced_accounts * 100) / U512::from(U256::MAX);
        // Make a simple time to finish estimation based on current progress
        // The estimation relies on account hashes being (close to) evenly distributed
        let remaining_accounts =
            (U512::from(U256::MAX) / 100) * (U512::from(100).saturating_sub(completion_rate));
        // Time to finish = Time since start / Accounts synced this cycle * Remaining accounts
        let time_to_finish_secs =
            U512::from(Instant::now().duration_since(data.cycle_start).as_secs())
                * remaining_accounts
                / synced_accounts_this_cycle;
        info!(
            "Downloading state trie, completion rate: {}%, estimated time to finish: {}",
            completion_rate,
            seconds_to_readable(time_to_finish_secs)
        );
        data.ended.iter().all(|e| *e)
    }
}

async fn show_state_sync_progress(progress: StateSyncProgress) {
    // Rest for one interval so we don't start computing on empty progress
    sleep(SHOW_PROGRESS_INTERVAL_DURATION).await;
    let mut interval = tokio::time::interval(SHOW_PROGRESS_INTERVAL_DURATION);
    let mut complete = false;
    while !complete {
        interval.tick().await;
        complete = progress.show_progress().await
    }
}
