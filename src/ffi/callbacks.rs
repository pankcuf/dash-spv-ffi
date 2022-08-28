extern crate libc;
use std::ffi::c_void;
use dash_spv_models::{llmq, masternode};
use dash_spv_primitives::crypto::byte_util::MutDecodable;
use dash_spv_primitives::crypto::UInt256;
use crate::ffi::from::FromFFI;
use crate::types;

pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void);
pub type ShouldProcessLLMQTypeCallback = unsafe extern "C" fn(llmq_type: u8, context: *const c_void) -> bool;
pub type ValidateLLMQCallback = unsafe extern "C" fn(data: *mut types::LLMQValidationData, context: *const c_void) -> bool;

pub type GetBlockHeightByHash = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> u32;
pub type MerkleRootLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut u8; // UIn256
pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *const types::MasternodeList;
pub type MasternodeListDestroy = unsafe extern "C" fn(masternode_list: *const types::MasternodeList);
pub type MasternodeListSave = unsafe extern "C" fn(block_hash: *mut [u8; 32], masternode_list: *const types::MasternodeList, context: *const c_void) -> bool;

pub type GetBlockHashByHeight = unsafe extern "C" fn(block_height: u32, context: *const c_void) -> *mut u8; // UIn256
pub type GetLLMQSnapshotByBlockHeight = unsafe extern "C" fn(block_height: u32, context: *const c_void) -> *const types::LLMQSnapshot;
pub type GetLLMQSnapshotByBlockHash = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *const types::LLMQSnapshot;
pub type SaveLLMQSnapshot = unsafe extern "C" fn(block_hash: *mut [u8; 32], snapshot: *const types::LLMQSnapshot, context: *const c_void) -> bool;
pub type LogMessage = unsafe extern "C" fn(message: *const libc::c_char, context: *const c_void);
pub type HashDestroy = unsafe extern "C" fn(hash: *mut u8);
pub type LLMQSnapshotDestroy = unsafe extern "C" fn(snapshot: *const types::LLMQSnapshot);

fn read_and_destroy_hash<DH>(lookup_result: *mut u8, destroy_hash: DH) -> Option<UInt256>
    where
        DH: Fn(*mut u8) {
    if !lookup_result.is_null() {
        let hash = UInt256::from_mut(lookup_result);
        destroy_hash(lookup_result);
        hash
    } else {
        None
    }
}

pub fn lookup_masternode_list<MNL, MND>(block_hash: UInt256, masternode_list_lookup: MNL, masternode_list_destroy: MND) -> Option<masternode::MasternodeList>
    where
        MNL: Fn(UInt256) -> *const types::MasternodeList + Copy,
        MND: Fn(*const types::MasternodeList) {
    let lookup_result = masternode_list_lookup(block_hash);
    if !lookup_result.is_null() {
        let data = unsafe { (*lookup_result).decode() };
        masternode_list_destroy(lookup_result);
        Some(data)
    } else {
        None
    }
}

pub fn lookup_block_hash_by_height<BL, DH>(block_height: u32, lookup: BL, destroy_hash: DH) -> Option<UInt256>
    where
        BL: Fn(u32) -> *mut u8 + Copy,
        DH: Fn(*mut u8) {
    read_and_destroy_hash(lookup(block_height), destroy_hash)
}

pub fn lookup_merkle_root_by_hash<MRL, DH>(block_hash: UInt256, lookup: MRL, destroy_hash: DH) -> Option<UInt256>
    where
        MRL: Fn(UInt256) -> *mut u8 + Copy,
        DH: Fn(*mut u8) {
    read_and_destroy_hash(lookup(block_hash), destroy_hash)
}

pub fn lookup_snapshot_by_block_hash<SL, SD>(block_hash: UInt256, snapshot_lookup: SL, snapshot_destroy: SD) -> Option<llmq::LLMQSnapshot>
    where
        SL: Fn(UInt256) -> *const types::LLMQSnapshot + Copy,
        SD: Fn(*const types::LLMQSnapshot)
{
    let lookup_result = snapshot_lookup(block_hash);
    if !lookup_result.is_null() {
        let data = unsafe { (*lookup_result).decode() };
        snapshot_destroy(lookup_result);
        Some(data)
    } else {
        None
    }
}

/*
pub type HashTestDestroy = unsafe extern "C" fn(hash: *mut u8);
pub type HashTestLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *mut u8; // UIn256

pub fn lookup_test_hash<MRL, DH>(block_hash: UInt256, lookup: MRL, destroy_hash: DH) -> Option<UInt256>
    where
        MRL: Fn(UInt256) -> *mut u8 + Copy,
        DH: Fn(*mut u8) {
    let lookup_result = lookup(block_hash);
    if !lookup_result.is_null() {

        let safe_bytes = unsafe { slice::from_raw_parts_mut(lookup_result, 32) };
        match safe_bytes.read_with::<UInt256>(&mut 0, byte::LE) {
            Ok(data) => {
                destroy_hash(lookup_result);
                Some(data)
            },
            Err(_err) => None
        }
    } else {
        None
    }
}*/
