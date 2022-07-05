use std::ffi::c_void;
use dash_spv_models::{llmq, masternode};
use dash_spv_primitives::crypto::byte_util::ConstDecodable;
use dash_spv_primitives::crypto::UInt256;
use crate::ffi::from::FromFFI;
use crate::types;

pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void);
pub type ShouldProcessLLMQTypeCallback = unsafe extern "C" fn(llmq_type: u8, context: *const c_void) -> bool;
pub type ValidateLLMQCallback = unsafe extern "C" fn(data: *mut types::LLMQValidationData, context: *const c_void) -> bool;

pub type GetBlockHeightByHash = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> u32;
pub type MerkleRootLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *const u8; // UIn256
pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *const types::MasternodeList;
pub type MasternodeListDestroy = unsafe extern "C" fn(*const types::MasternodeList);

pub type UniversalLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> u32;

pub type GetBlockHashByHeight = unsafe extern "C" fn(block_height: u32, context: *const c_void) -> *const u8; // UIn256
pub type GetLLMQSnapshotByBlockHeight = unsafe extern "C" fn(block_height: u32, context: *const c_void) -> *const types::LLMQSnapshot;

pub fn lookup_masternode_list<MNL, MND>(block_hash: UInt256, masternode_list_lookup: MNL, _masternode_list_destroy: MND) -> Option<masternode::MasternodeList>
    where
        MNL: Fn(UInt256) -> *const types::MasternodeList + Copy,
        MND: Fn(*const types::MasternodeList) {
    let lookup_result = masternode_list_lookup(block_hash);
    if !lookup_result.is_null() {
        let data = unsafe { (*lookup_result).decode() };
        // masternode_list_destroy(data)
        Some(data)
    } else {
        None
    }
}

pub fn lookup_block_hash_by_height<BL>(block_height: u32, lookup: BL) -> Option<UInt256>
    where BL: Fn(u32) -> *const u8 + Copy {
    let lookup_result = lookup(block_height);
    if !lookup_result.is_null() {
        UInt256::from_const(lookup_result)
    } else {
        None
    }
}

pub fn lookup_merkle_root_by_hash<MRL>(block_hash: UInt256, lookup: MRL) -> Option<UInt256>
    where MRL: Fn(UInt256) -> *const u8 + Copy {
    let lookup_result = lookup(block_hash);
    if !lookup_result.is_null() {
        UInt256::from_const(lookup_result)
    } else {
        None
    }
}

pub fn lookup_snapshot<'a, SL>(block_height: u32, snapshot_lookup: SL) -> Option<llmq::LLMQSnapshot>
    where SL: Fn(u32) -> *const types::LLMQSnapshot + Copy {
    let lookup_result = snapshot_lookup(block_height);
    if !lookup_result.is_null() {
        let data = unsafe { (*lookup_result).decode() };
        Some(data)
    } else {
        None
    }
}
