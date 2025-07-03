use ethrex_common::H256;
use ethrex_storage::{STATE_TRIE_SEGMENTS, Store, error::StoreError};
use ethrex_trie::EMPTY_TRIE_HASH;

use super::STATE_TRIE_SEGMENTS_START;

#[derive(Debug, PartialEq)]
pub struct SnapSyncStatus {
    pub header_download_checkpoint: H256,
    pub state_trie_key_checkpoint: [H256; STATE_TRIE_SEGMENTS],
    pub state_trie_rebuild_checkpoint: (H256, [H256; STATE_TRIE_SEGMENTS]),
    pub storage_trie_rebuild_pending: Vec<(H256, H256)>,
}

impl Default for SnapSyncStatus {
    fn default() -> Self {
        Self {
            header_download_checkpoint: H256::zero(),
            state_trie_key_checkpoint: *STATE_TRIE_SEGMENTS_START,
            state_trie_rebuild_checkpoint: (*EMPTY_TRIE_HASH, *STATE_TRIE_SEGMENTS_START),
            storage_trie_rebuild_pending: Vec::new(),
        }
    }
}

impl SnapSyncStatus {
    pub async fn read_from_store(store: Store) -> Result<Self, StoreError> {
        let header_download_checkpoint = store
            .get_header_download_checkpoint()
            .await?
            .unwrap_or_default();
        let state_trie_key_checkpoint = store
            .get_state_trie_key_checkpoint()
            .await?
            .unwrap_or(*STATE_TRIE_SEGMENTS_START);
        let state_trie_rebuild_checkpoint = store
            .get_state_trie_rebuild_checkpoint()
            .await?
            .unwrap_or((*EMPTY_TRIE_HASH, *STATE_TRIE_SEGMENTS_START));
        let storage_trie_rebuild_pending = store
            .get_storage_trie_rebuild_pending()
            .await?
            .unwrap_or_default();
        Ok(Self {
            header_download_checkpoint,
            state_trie_key_checkpoint,
            state_trie_rebuild_checkpoint,
            storage_trie_rebuild_pending,
        })
    }

    pub(crate) fn is_empty(&self) -> bool {
        self == &Self::default()
    }

    pub(crate) fn clear(&mut self) {
        *self = Self::default()
    }

    pub async fn write_to_store(&self, store: Store) -> Result<(), StoreError> {
        // If the status is empty (aka no snap sync took place, or snap sync was concreted) clear the status from the DB
        if self.is_empty() {
            store.clear_snap_state().await?;
        } else {
            store
                .set_header_download_checkpoint(self.header_download_checkpoint)
                .await?;
            store
                .set_state_trie_key_checkpoint(self.state_trie_key_checkpoint)
                .await?;
            store
                .set_state_trie_rebuild_checkpoint(self.state_trie_rebuild_checkpoint)
                .await?;
            store
                .set_storage_trie_rebuild_pending(self.storage_trie_rebuild_pending.clone())
                .await?;
        }
        Ok(())
    }
}
