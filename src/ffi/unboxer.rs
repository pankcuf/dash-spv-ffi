#![allow(unused_variables)]
#![allow(dead_code)]
use crate::types;

pub unsafe fn unbox_any<T: ?Sized>(any: *mut T) -> Box<T> {
    Box::from_raw(any)
}

pub unsafe fn unbox_vec<T>(vec: Vec<*mut T>) -> Vec<Box<T>> {
    vec.iter().map(|&x| unbox_any(x)).collect()
}

pub unsafe fn unbox_vec_ptr<T>(ptr: *mut T, count: usize) -> Vec<T> {
    Vec::from_raw_parts(ptr, count, count)
}

pub unsafe fn unbox_masternode_entry(x: *mut types::MasternodeEntry) {
    let entry = unbox_any(x);
    unbox_any(entry.confirmed_hash);
    if !entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null() {
        unbox_any(entry.confirmed_hash_hashed_with_provider_registration_transaction_hash);
    }
    unbox_any(entry.key_id_voting);
    unbox_any(entry.entry_hash);
    unbox_any(entry.operator_public_key);
    unbox_vec_ptr(entry.previous_entry_hashes, entry.previous_entry_hashes_count);
    unbox_vec_ptr(entry.previous_operator_public_keys, entry.previous_operator_public_keys_count);
    unbox_vec_ptr(entry.previous_validity, entry.previous_validity_count);
    unbox_any(entry.provider_registration_transaction_hash);
    unbox_any(entry.ip_address);
}

pub unsafe fn unbox_llmq_entry(x: *mut types::LLMQEntry) {
    let entry = unbox_any(x);
    unbox_any(entry.all_commitment_aggregated_signature);
    if !entry.commitment_hash.is_null() {
        unbox_any(entry.commitment_hash);
    }
    // println!("unbox_llmq_entry.entry_hash: {:?}", entry.entry_hash);
    unbox_any(entry.entry_hash);
    // println!("unbox_llmq_entry.llmq_hash =>: {:?}", entry.llmq_hash);
    unbox_any(entry.llmq_hash);
    unbox_any(entry.public_key);
    unbox_any(entry.threshold_signature);
    unbox_any(entry.verification_vector_hash);
    let signers_bitset = std::ptr::slice_from_raw_parts_mut::<u8>(entry.signers_bitset, entry.signers_bitset_length);
    let valid_members_bitset = std::ptr::slice_from_raw_parts_mut::<u8>(entry.valid_members_bitset, entry.valid_members_bitset_length);
    unbox_any(signers_bitset);
    unbox_any(valid_members_bitset);
}

pub unsafe fn unbox_llmq_map(x: *mut types::LLMQMap) {
    let entry = unbox_any(x);
    let values = unbox_vec_ptr(entry.values, entry.count);
    for &x in values.iter() {
        unbox_llmq_entry(x);
    }
}
pub unsafe fn unbox_masternode_list(masternode_list: Box<types::MasternodeList>) {
    unbox_any(masternode_list.block_hash);
    if !masternode_list.masternode_merkle_root.is_null() {
        unbox_any(masternode_list.masternode_merkle_root);
    }
    if !masternode_list.llmq_merkle_root.is_null() {
        unbox_any(masternode_list.llmq_merkle_root);
    }
    unbox_masternode_vec(unbox_vec_ptr(masternode_list.masternodes, masternode_list.masternodes_count));
    unbox_llmq_map_vec(unbox_vec_ptr(masternode_list.llmq_type_maps, masternode_list.llmq_type_maps_count));
}

pub unsafe fn unbox_masternode_vec(vec: Vec<*mut types::MasternodeEntry>) {
    for &x in vec.iter() {
        unbox_masternode_entry(x);
    }
}
pub unsafe fn unbox_llmq_vec(vec: Vec<*mut types::LLMQEntry>) {
    for &x in vec.iter() {
        unbox_llmq_entry(x);
    }
}

pub unsafe fn unbox_llmq_map_vec(vec: Vec<*mut types::LLMQMap>) {
    for &x in vec.iter() {
        unbox_llmq_map(x);
    }
}

pub unsafe fn unbox_llmq_hash_vec(vec: Vec<*mut types::LLMQTypedHash>) {
    for &x in vec.iter() {
        unbox_llmq_typed_hash(x);
    }
}

pub unsafe fn unbox_llmq_typed_hash(typed_hash: *mut types::LLMQTypedHash) {
    let hash = unbox_any(typed_hash);
    unbox_any(hash.llmq_hash);
}

pub unsafe fn unbox_llmq_validation_data(llmq_validation_data: *mut types::LLMQValidationData) {
    let result = unbox_any(llmq_validation_data);
    unbox_any(result.all_commitment_aggregated_signature);
    unbox_any(result.commitment_hash);
    unbox_any(result.public_key);
    unbox_any(result.threshold_signature);
    unbox_vec(unbox_vec_ptr(result.items, result.count));
}

pub unsafe fn unbox_snapshot_vec(vec: Vec<*mut types::LLMQSnapshot>) {
    for &x in vec.iter() {
        unbox_llmq_snapshot(x);
    }
}

pub unsafe fn unbox_mn_list_diff_vec(vec: Vec<*mut types::MNListDiff>) {
    for &x in vec.iter() {
        unbox_mn_list_diff(x);
    }
}

pub unsafe fn unbox_mn_list_diff_result_vec(vec: Vec<*mut types::MNListDiffResult>) {
    for &x in vec.iter() {
        unbox_result(x);
    }
}
pub unsafe fn unbox_block(block: *mut types::Block) {
    let result = unbox_any(block);
    unbox_any(result.hash);
}

pub unsafe fn unbox_llmq_indexed_hash(indexed_hash: *mut types::LLMQIndexedHash) {
    let result = unbox_any(indexed_hash);
    unbox_any(result.hash);
}

pub unsafe fn unbox_llmq_snapshot(quorum_snapshot: *mut types::LLMQSnapshot) {
    let result = unbox_any(quorum_snapshot);
    unbox_vec_ptr(result.member_list, result.member_list_length);
}
pub unsafe fn unbox_tx_input(result: *mut types::TransactionInput) {
    let input = unbox_any(result);
    unbox_any(input.input_hash);
    if !input.script.is_null() && input.script_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(input.script, input.script_length) as *mut [u8]);
    }
    if !input.signature.is_null() && input.signature_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(input.signature, input.signature_length) as *mut [u8]);
    }
}
pub unsafe fn unbox_tx_output(result: *mut types::TransactionOutput) {
    let output = unbox_any(result);
    if !output.script.is_null() && output.script_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(output.script, output.script_length) as *mut [u8]);
    }
    if !output.address.is_null() && output.address_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(output.address, output.address_length) as *mut [u8]);
    }
}
pub unsafe fn unbox_tx_input_vec(result: Vec<*mut types::TransactionInput>) {
    for &x in result.iter() {
        unbox_tx_input(x);
    }
}
pub unsafe fn unbox_tx_output_vec(result: Vec<*mut types::TransactionOutput>) {
    for &x in result.iter() {
        unbox_tx_output(x);
    }
}
pub unsafe fn unbox_tx(result: *mut types::Transaction) {
    let tx = unbox_any(result);
    unbox_tx_input_vec(unbox_vec_ptr(tx.inputs, tx.inputs_count));
    unbox_tx_output_vec(unbox_vec_ptr(tx.outputs, tx.outputs_count));
    unbox_any(tx.tx_hash);
}

pub unsafe fn unbox_coinbase_tx(result: *mut types::CoinbaseTransaction) {
    let ctx = unbox_any(result);
    unbox_tx(ctx.base);
    unbox_any(ctx.merkle_root_mn_list);
    if !ctx.merkle_root_llmq_list.is_null() {
        unbox_any(ctx.merkle_root_llmq_list);
    }
}

pub unsafe fn unbox_result(result: *mut types::MNListDiffResult) {
    let res = unbox_any(result);
    unbox_any(res.block_hash);
    unbox_masternode_list(unbox_any(res.masternode_list));
    unbox_vec(unbox_vec_ptr(res.needed_masternode_lists, res.needed_masternode_lists_count));
    unbox_masternode_vec(unbox_vec_ptr(res.added_masternodes, res.added_masternodes_count));
    unbox_masternode_vec(unbox_vec_ptr(res.modified_masternodes, res.modified_masternodes_count));
    unbox_llmq_map_vec(unbox_vec_ptr(res.added_llmq_type_maps, res.added_llmq_type_maps_count));
}
pub unsafe fn unbox_mn_list_diff(result: *mut types::MNListDiff) {
    let list_diff = unbox_any(result);
    unbox_any(list_diff.base_block_hash);
    unbox_any(list_diff.block_hash);
    unbox_any(std::ptr::slice_from_raw_parts_mut(list_diff.merkle_hashes, list_diff.merkle_hashes_count) as *mut [u8]);
    unbox_any(std::ptr::slice_from_raw_parts_mut(list_diff.merkle_flags, list_diff.merkle_flags_count) as *mut [u8]);
    unbox_coinbase_tx(list_diff.coinbase_transaction);

    unbox_vec(unbox_vec_ptr(list_diff.deleted_masternode_hashes, list_diff.deleted_masternode_hashes_count));
    unbox_masternode_vec(unbox_vec_ptr(list_diff.added_or_modified_masternodes, list_diff.added_or_modified_masternodes_count));
    unbox_llmq_hash_vec(unbox_vec_ptr(list_diff.deleted_quorums, list_diff.deleted_quorums_count));

    unbox_llmq_vec(unbox_vec_ptr(list_diff.added_quorums, list_diff.added_quorums_count));
}

pub unsafe fn unbox_llmq_rotation_info(result: *mut types::LLMQRotationInfo) {
    let res = unbox_any(result);
    unbox_llmq_snapshot(res.snapshot_at_h_c);
    unbox_llmq_snapshot(res.snapshot_at_h_2c);
    unbox_llmq_snapshot(res.snapshot_at_h_3c);
    unbox_mn_list_diff(res.mn_list_diff_tip);
    unbox_mn_list_diff(res.mn_list_diff_at_h);
    unbox_mn_list_diff(res.mn_list_diff_at_h_c);
    unbox_mn_list_diff(res.mn_list_diff_at_h_2c);
    unbox_mn_list_diff(res.mn_list_diff_at_h_3c);
    if res.extra_share {
        unbox_llmq_snapshot(res.snapshot_at_h_4c);
        unbox_mn_list_diff(res.mn_list_diff_at_h_4c);
    }
    unbox_vec(unbox_vec_ptr(res.last_quorum_per_index, res.last_quorum_per_index_count));
    unbox_snapshot_vec(unbox_vec_ptr(res.quorum_snapshot_list, res.quorum_snapshot_list_count));
    unbox_mn_list_diff_vec(unbox_vec_ptr(res.mn_list_diff_list, res.mn_list_diff_list_count));
}
pub unsafe fn unbox_llmq_rotation_info_result(result: *mut types::LLMQRotationInfoResult) {
    let res = unbox_any(result);
    unbox_result(res.result_at_tip);
    unbox_result(res.result_at_h);
    unbox_result(res.result_at_h_c);
    unbox_result(res.result_at_h_2c);
    unbox_result(res.result_at_h_3c);
    unbox_llmq_snapshot(res.snapshot_at_h_c);
    unbox_llmq_snapshot(res.snapshot_at_h_2c);
    unbox_llmq_snapshot(res.snapshot_at_h_3c);
    if res.extra_share {
        unbox_result(res.result_at_h_4c);
        unbox_llmq_snapshot(res.snapshot_at_h_4c);
    }
    unbox_llmq_vec(unbox_vec_ptr(res.last_quorum_per_index, res.last_quorum_per_index_count));
    unbox_snapshot_vec(unbox_vec_ptr(res.quorum_snapshot_list, res.quorum_snapshot_list_count));
    unbox_mn_list_diff_result_vec(unbox_vec_ptr(res.mn_list_diff_list, res.mn_list_diff_list_count));
    // unbox_mn_list_diff_vec(unbox_vec_ptr(res.mn_list_diff_list, res.mn_list_diff_list_count));
}
