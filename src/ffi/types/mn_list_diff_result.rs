use std::ptr::null_mut;
use crate::ffi;

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct MNListDiffResult {
    pub block_hash: *mut [u8; 32],
    pub has_found_coinbase: bool, //1 byte
    pub has_valid_coinbase: bool, //1 byte
    pub has_valid_mn_list_root: bool, //1 byte
    pub has_valid_llmq_list_root: bool, //1 byte
    pub has_valid_quorums: bool, //1 byte
    pub masternode_list: *mut ffi::types::MasternodeList,
    pub added_masternodes: *mut *mut ffi::types::MasternodeEntry,
    pub added_masternodes_count: usize,
    pub modified_masternodes: *mut *mut ffi::types::MasternodeEntry,
    pub modified_masternodes_count: usize,
    pub added_llmq_type_maps: *mut *mut ffi::types::LLMQMap,
    pub added_llmq_type_maps_count: usize,
    pub needed_masternode_lists:  *mut *mut [u8; 32], // [u8; 32]
    pub needed_masternode_lists_count: usize,
}

impl Default for MNListDiffResult {
    fn default() -> Self {
        MNListDiffResult {
            block_hash: null_mut(),
            has_found_coinbase: false,
            has_valid_coinbase: false,
            has_valid_mn_list_root: false,
            has_valid_llmq_list_root: false,
            has_valid_quorums: false,
            masternode_list: null_mut(),
            added_masternodes: null_mut(),
            added_masternodes_count: 0,
            modified_masternodes: null_mut(),
            modified_masternodes_count: 0,
            added_llmq_type_maps: null_mut(),
            added_llmq_type_maps_count: 0,
            needed_masternode_lists: null_mut(),
            needed_masternode_lists_count: 0
        }
    }
}
