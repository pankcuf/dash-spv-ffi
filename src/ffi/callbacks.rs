use std::ffi::c_void;
use crate::types;

pub type AddInsightBlockingLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void);
pub type ShouldProcessLLMQTypeCallback = unsafe extern "C" fn(llmq_type: u8, context: *const c_void) -> bool;
pub type ValidateLLMQCallback = unsafe extern "C" fn(data: *mut types::LLMQValidationData, context: *const c_void) -> bool;

pub type BlockHeightLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> u32;
pub type MasternodeListLookup = unsafe extern "C" fn(block_hash: *mut [u8; 32], context: *const c_void) -> *const types::MasternodeList;
pub type MasternodeListDestroy = unsafe extern "C" fn(*const types::MasternodeList);