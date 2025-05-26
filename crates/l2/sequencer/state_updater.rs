use std::{sync::Arc, time::Duration};

use ethrex_blockchain::{error::InvalidForkChoice, fork_choice::apply_fork_choice};
use ethrex_common::{types::Block, Address};
use ethrex_l2_sdk::calldata::encode_calldata;
use ethrex_rpc::{clients::Overrides, EthClient};
use ethrex_storage::Store;
use ethrex_storage_rollup::StoreRollup;
use tokio::{sync::Mutex, time::sleep};
use tracing::{error, info, warn};

use crate::{utils::parse::hash_to_address, SequencerConfig};

use super::{
    errors::{SequencerError, StateUpdaterError},
    SequencerState,
};

pub struct StateUpdater {
    on_chain_proposer_address: Address,
    sequencer_registry_address: Address,
    sequencer_address: Address,
    eth_client: Arc<EthClient>,
    store: Store,
    rollup_store: StoreRollup,
    check_interval_ms: u64,
}

pub async fn start_state_updater(
    sequencer_cfg: SequencerConfig,
    sequencer_state: Arc<Mutex<SequencerState>>,
    store: Store,
    rollup_store: StoreRollup,
) -> Result<(), SequencerError> {
    let state_updater = StateUpdater::new(sequencer_cfg, store, rollup_store)?;
    state_updater.run(sequencer_state).await;
    Ok(())
}

impl StateUpdater {
    pub fn new(
        sequencer_cfg: SequencerConfig,
        store: Store,
        rollup_store: StoreRollup,
    ) -> Result<Self, StateUpdaterError> {
        Ok(Self {
            on_chain_proposer_address: sequencer_cfg.l1_committer.on_chain_proposer_address,
            sequencer_registry_address: sequencer_cfg.state_updater.sequencer_registry,
            sequencer_address: sequencer_cfg.l1_committer.l1_address,
            eth_client: Arc::new(EthClient::new_with_multiple_urls(
                sequencer_cfg.eth.rpc_url.clone(),
            )?),
            store,
            rollup_store,
            check_interval_ms: sequencer_cfg.state_updater.check_interval_ms,
        })
    }

    pub async fn run(&self, sequencer_state: Arc<Mutex<SequencerState>>) {
        loop {
            if let Err(err) = self.main_logic(sequencer_state.clone()).await {
                error!("State Updater Error: {}", err);
            }

            sleep(Duration::from_millis(self.check_interval_ms)).await;
        }
    }

    pub async fn main_logic(
        &self,
        sequencer_state: Arc<Mutex<SequencerState>>,
    ) -> Result<(), StateUpdaterError> {
        let calldata = encode_calldata("leaderSequencer()", &[])?;

        let lead_sequencer = hash_to_address(
            self.eth_client
                .call(
                    self.sequencer_registry_address,
                    calldata.into(),
                    Overrides::default(),
                )
                .await?
                .parse()
                .map_err(|_| {
                    StateUpdaterError::CalldataParsingError(
                        "Failed to parse leaderSequencer() return data".to_string(),
                    )
                })?,
        );

        let node_is_up_to_date = self.node_is_up_to_date().await?;

        let new_state = if lead_sequencer == self.sequencer_address {
            if node_is_up_to_date {
                SequencerState::Sequencing
            } else {
                warn!("Node should transition to sequencing but it is not up to date, continue syncing.");
                SequencerState::Following
            }
        } else {
            SequencerState::Following
        };

        let mut current_state = sequencer_state.lock().await;

        match (current_state.clone(), new_state.clone()) {
            (SequencerState::Sequencing, SequencerState::Sequencing)
            | (SequencerState::Following, SequencerState::Following) => {}
            (SequencerState::Sequencing, SequencerState::Following) => {
                info!("Now the follower sequencer. Stopping sequencing.");
                self.revert_uncommitted_state().await?;
            }
            (SequencerState::Following, SequencerState::Sequencing) => {
                info!("Now the lead sequencer. Starting sequencing.");
            }
        };

        *current_state = new_state;

        Ok(())
    }

    async fn node_is_up_to_date(&self) -> Result<bool, StateUpdaterError> {
        let last_committed_batch_number = self
            .eth_client
            .get_last_committed_batch(self.on_chain_proposer_address)
            .await?;

        self.rollup_store
            .contains_batch(&last_committed_batch_number)
            .await
            .map_err(StateUpdaterError::StoreError)
    }

    // Sequencing -> Following
    // 1. Last batch was sealed
    //  a. And committed -> no uncommitted state to revert
    //  b. And not committed -> revert uncommitted state
    // 2. Last bast was not sealed
    //  a. No more blocks were added -> no uncommitted state to revert
    //  b. Some blocks were added -> revert uncommitted state
    async fn revert_uncommitted_state(&self) -> Result<(), StateUpdaterError> {
        let last_l2_committed_batch = self
            .eth_client
            .get_last_committed_batch(self.on_chain_proposer_address)
            .await?;

        info!("Last committed batch: {last_l2_committed_batch:#x}");

        let Some(last_l2_committed_batch_blocks) = self
            .rollup_store
            .get_block_numbers_by_batch(last_l2_committed_batch)
            .await?
        else {
            // Node is not up to date. There is no uncommitted state to revert.
            info!("No uncommitted state to revert. Node is up to date.");
            return Ok(());
        };

        info!(
            "Last committed batch blocks: {:?}",
            last_l2_committed_batch_blocks
        );

        let Some(last_l2_committed_batch_block_number) = last_l2_committed_batch_blocks.last()
        else {
            return Err(StateUpdaterError::InternalError(
                "No blocks found for the last committed batch".to_string(),
            ));
        };
        self.store
            .update_latest_block_number(*last_l2_committed_batch_block_number)
            .await?;

        info!("Last committed batch block number: {last_l2_committed_batch_block_number}");

        let last_l2_committed_batch_block_body = self
            .store
            .get_block_body(*last_l2_committed_batch_block_number)
            .await?
            .ok_or(StateUpdaterError::InternalError(
                "No block body found for the last committed batch block number".to_string(),
            ))?;

        let last_l2_committed_batch_block_header = self
            .store
            .get_block_header(*last_l2_committed_batch_block_number)?
            .ok_or(StateUpdaterError::InternalError(
                "No block header found for the last committed batch block number".to_string(),
            ))?;

        let last_l2_committed_batch_block = Block::new(
            last_l2_committed_batch_block_header,
            last_l2_committed_batch_block_body,
        );

        let last_l2_committed_batch_block_hash = last_l2_committed_batch_block.hash();

        info!("Reverting uncommitted state to the last committed batch block {last_l2_committed_batch_block_number} with hash {last_l2_committed_batch_block_hash:#x}");

        match apply_fork_choice(
            &self.store,
            last_l2_committed_batch_block_hash,
            last_l2_committed_batch_block_hash,
            last_l2_committed_batch_block_hash,
        )
        .await
        {
            Ok(_) | Err(InvalidForkChoice::NewHeadAlreadyCanonical) => Ok(()),
            Err(err) => Err(err.into()),
        }
    }
}
