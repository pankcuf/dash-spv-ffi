use std::ptr::null_mut;
use crate::types;

#[repr(C)] #[derive(Clone, Copy, Debug)]
pub struct LLMQRotationInfoResult {
    pub result_at_tip: *mut types::MNListDiffResult,
    pub result_at_h: *mut types::MNListDiffResult,
    pub result_at_h_c: *mut types::MNListDiffResult,
    pub result_at_h_2c: *mut types::MNListDiffResult,
    pub result_at_h_3c: *mut types::MNListDiffResult,
    pub result_at_h_4c: *mut types::MNListDiffResult,

    pub snapshot_at_h_c: *mut types::LLMQSnapshot,
    pub snapshot_at_h_2c: *mut types::LLMQSnapshot,
    pub snapshot_at_h_3c: *mut types::LLMQSnapshot,
    pub snapshot_at_h_4c: *mut types::LLMQSnapshot,
    pub extra_share: bool,
}

impl Default for LLMQRotationInfoResult {
    fn default() -> Self {
        Self {
            result_at_tip: null_mut(),
            result_at_h: null_mut(),
            result_at_h_c: null_mut(),
            result_at_h_2c: null_mut(),
            result_at_h_3c: null_mut(),
            result_at_h_4c: null_mut(),
            snapshot_at_h_c: null_mut(),
            snapshot_at_h_2c: null_mut(),
            snapshot_at_h_3c: null_mut(),
            snapshot_at_h_4c: null_mut(),
            extra_share: false
        }
    }
}
