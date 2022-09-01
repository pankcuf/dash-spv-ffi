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
    println!("unbox_masternode_entry: {:?}", x);
    let entry = unbox_any(x);
    println!("unbox_masternode_entry.confirmed_hash: {:?}", entry.confirmed_hash);
    unbox_any(entry.confirmed_hash);
    if !entry.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null() {
        println!("unbox_masternode_entry.confirmed_hash_hashed_with_provider_registration_transaction_hash: {:?}", entry.confirmed_hash_hashed_with_provider_registration_transaction_hash);
        unbox_any(entry.confirmed_hash_hashed_with_provider_registration_transaction_hash);
    }
    println!("unbox_masternode_entry.key_id_voting: {:?}", entry.key_id_voting);
    unbox_any(entry.key_id_voting);
    println!("unbox_masternode_entry.entry_hash: {:?}", entry.entry_hash);
    unbox_any(entry.entry_hash);
    println!("unbox_masternode_entry.operator_public_key: {:?}", entry.operator_public_key);
    unbox_any(entry.operator_public_key);
    println!("unbox_masternode_entry.previous_entry_hashes: {:?}", entry.previous_entry_hashes);
    unbox_vec_ptr(entry.previous_entry_hashes, entry.previous_entry_hashes_count);
    println!("unbox_masternode_entry.previous_operator_public_keys: {:?}", entry.previous_operator_public_keys);
    unbox_vec_ptr(entry.previous_operator_public_keys, entry.previous_operator_public_keys_count);
    println!("unbox_masternode_entry.previous_validity: {:?}", entry.previous_validity);
    unbox_vec_ptr(entry.previous_validity, entry.previous_validity_count);
    println!("unbox_masternode_entry.provider_registration_transaction_hash: {:?}", entry.provider_registration_transaction_hash);
    unbox_any(entry.provider_registration_transaction_hash);
    println!("unbox_masternode_entry.ip_address: {:?}", entry.ip_address);
    unbox_any(entry.ip_address);
}

pub unsafe fn unbox_llmq_entry(x: *mut types::LLMQEntry) {
    println!("unbox_llmq_entry: {:?}", x);
    let entry = unbox_any(x);
    println!("unbox_llmq_entry.all_commitment_aggregated_signature: {:?}", entry.all_commitment_aggregated_signature);
    unbox_any(entry.all_commitment_aggregated_signature);
    assert!(entry.all_commitment_aggregated_signature.is_null(), "entry.all_commitment_aggregated_signature not destroed");
    if !entry.commitment_hash.is_null() {
        println!("unbox_llmq_entry.commitment_hash: {:?}", entry.commitment_hash);
        unbox_any(entry.commitment_hash);
    }
    assert!(entry.commitment_hash.is_null(), "entry.commitment_hash not destroed");
    println!("unbox_llmq_entry.entry_hash: {:?}", entry.entry_hash);
    unbox_any(entry.entry_hash);
    assert!(entry.entry_hash.is_null(), "entry.entry_hash not destroed");
    println!("unbox_llmq_entry.llmq_hash: {:?}", entry.llmq_hash);
    unbox_any(entry.llmq_hash);
    assert!(entry.llmq_hash.is_null(), "entry.llmq_hash not destroed");
    println!("unbox_llmq_entry.public_key: {:?}", entry.public_key);
    unbox_any(entry.public_key);
    assert!(entry.public_key.is_null(), "entry.public_key not destroed");
    println!("unbox_llmq_entry.threshold_signature: {:?}", entry.threshold_signature);
    unbox_any(entry.threshold_signature);
    assert!(entry.threshold_signature.is_null(), "entry.threshold_signature not destroed");
    println!("unbox_llmq_entry.verification_vector_hash: {:?}", entry.verification_vector_hash);
    unbox_any(entry.verification_vector_hash);
    assert!(entry.verification_vector_hash.is_null(), "entry.verification_vector_hash not destroed");
    println!("unbox_llmq_entry.signers_bitset {:?}", entry.signers_bitset);
    //unbox_vec_ptr(entry.signers_bitset, entry.signers_bitset_length);
    unbox_any(std::ptr::slice_from_raw_parts_mut::<u8>(entry.signers_bitset, entry.signers_bitset_length));
    assert!(entry.signers_bitset.is_null(), "entry.signers_bitset not destroed");
    println!("unbox_llmq_entry.valid_members_bitset {:?}", entry.valid_members_bitset);
    //unbox_vec_ptr(entry.valid_members_bitset, entry.valid_members_bitset_length);
    unbox_any(std::ptr::slice_from_raw_parts_mut::<u8>(entry.valid_members_bitset, entry.valid_members_bitset_length));
    assert!(entry.valid_members_bitset.is_null(), "entry.valid_members_bitset not destroed");
}

pub unsafe fn unbox_llmq_map(x: *mut types::LLMQMap) {
    println!("unbox_llmq_map: {:?}", x);
    let entry = unbox_any(x);
    println!("unbox_llmq_map.values: {:?}", entry.values);
    let values = unbox_vec_ptr(entry.values, entry.count);
    for &x in values.iter() {
        unbox_llmq_entry(x);
        assert!(entry.x.is_null(), "unbox_llmq_map.entry not destroed");
    }
}
pub unsafe fn unbox_masternode_list(list: *mut types::MasternodeList) {
    println!("unbox_masternode_list: {:?}", list);
    let masternode_list = unbox_any(list);
    println!("unbox_masternode_list.block_hash: {:?}", masternode_list.block_hash);
    unbox_any(masternode_list.block_hash);
    assert!(masternode_list.block_hash.x.is_null(), "masternode_list.block_hash not destroed");
    if !masternode_list.masternode_merkle_root.is_null() {
        println!("unbox_masternode_list.masternode_merkle_root: {:?}", masternode_list.masternode_merkle_root);
        unbox_any(masternode_list.masternode_merkle_root);
    }
    assert!(masternode_list.masternode_merkle_root.x.is_null(), "masternode_list.masternode_merkle_root not destroed");
    if !masternode_list.llmq_merkle_root.is_null() {
        println!("unbox_masternode_list.llmq_merkle_root: {:?}", masternode_list.llmq_merkle_root);
        unbox_any(masternode_list.llmq_merkle_root);
    }
    assert!(masternode_list.llmq_merkle_root.x.is_null(), "masternode_list.llmq_merkle_root not destroed");
    println!("unbox_masternode_list.masternodes: {:?}", masternode_list.masternodes);
    unbox_masternode_vec(unbox_vec_ptr(masternode_list.masternodes, masternode_list.masternodes_count));
    assert!(masternode_list.masternodes.is_null(), "masternode_list.masternodes not destroed");
    println!("unbox_masternode_list.llmq_type_maps: {:?}", masternode_list.llmq_type_maps);
    unbox_llmq_map_vec(unbox_vec_ptr(masternode_list.llmq_type_maps, masternode_list.llmq_type_maps_count));
    assert!(masternode_list.llmq_type_maps.is_null(), "masternode_list.llmq_type_maps not destroed");
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
    println!("unbox_llmq_typed_hash: {:?}", typed_hash);
    let hash = unbox_any(typed_hash);
    println!("unbox_llmq_typed_hash.llmq_hash: {:?}", hash.llmq_hash);
    unbox_any(hash.llmq_hash);
}

pub unsafe fn unbox_llmq_validation_data(llmq_validation_data: *mut types::LLMQValidationData) {
    let result = unbox_any(llmq_validation_data);
    println!("unbox_llmq_validation_data: {:?}", llmq_validation_data);
    println!("unbox_llmq_entry.all_commitment_aggregated_signature.: {:?}", result.all_commitment_aggregated_signature);
    unbox_any(result.all_commitment_aggregated_signature);
    println!("unbox_llmq_entry.commitment_hash.: {:?}", result.commitment_hash);
    unbox_any(result.commitment_hash);
    println!("unbox_llmq_entry.public_key.: {:?}", result.public_key);
    unbox_any(result.public_key);
    println!("unbox_llmq_entry.threshold_signature.: {:?}", result.threshold_signature);
    unbox_any(result.threshold_signature);
    println!("unbox_llmq_entry.items.: {:?}", result.items);
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
        unbox_mn_list_diff_result(x);
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
    println!("unbox_llmq_snapshot: {:?}", quorum_snapshot);
    let result = unbox_any(quorum_snapshot);
    // unbox_vec_ptr(result.member_list, result.member_list_length);
    println!("unbox_llmq_snapshot.member_list: {:?}", result.member_list);
    unbox_any(std::ptr::slice_from_raw_parts_mut::<u8>(result.member_list, result.member_list_length));
    // TODO: AAA
    println!("unbox_llmq_snapshot.skip_list: {:?}", result.skip_list);
    unbox_any(std::ptr::slice_from_raw_parts_mut::<u32>(result.skip_list, result.skip_list_length));
    // unbox_vec_ptr(result.skip_list, result.skip_list_length);
}
pub unsafe fn unbox_tx_input(result: *mut types::TransactionInput) {
    println!("unbox_tx_input: {:?}", result);
    let input = unbox_any(result);
    println!("unbox_tx_input.input_hash: {:?}", input.input_hash);
    unbox_any(input.input_hash);
    println!("unbox_tx_input.script: {:?}", input.script);
    if !input.script.is_null() && input.script_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(input.script, input.script_length) as *mut [u8]);
    }
    println!("unbox_tx_input.signature: {:?}", input.signature);
    if !input.signature.is_null() && input.signature_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(input.signature, input.signature_length) as *mut [u8]);
    }
}
pub unsafe fn unbox_tx_output(result: *mut types::TransactionOutput) {
    println!("unbox_tx_output: {:?}", result);
    let output = unbox_any(result);
    println!("unbox_tx_output.signature: {:?}", output.script);
    if !output.script.is_null() && output.script_length > 0 {
        unbox_any(std::ptr::slice_from_raw_parts_mut(output.script, output.script_length) as *mut [u8]);
    }
    println!("unbox_tx_output.address: {:?}", output.address);
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
    println!("unbox_tx: {:?}", result);
    let tx = unbox_any(result);
    println!("unbox_tx.inputs: {:?}", tx.inputs);
    unbox_tx_input_vec(unbox_vec_ptr(tx.inputs, tx.inputs_count));
    println!("unbox_tx.outputs: {:?}", tx.outputs);
    unbox_tx_output_vec(unbox_vec_ptr(tx.outputs, tx.outputs_count));
    println!("unbox_tx.tx_hash: {:?}", tx.tx_hash);
    unbox_any(tx.tx_hash);
}

pub unsafe fn unbox_coinbase_tx(result: *mut types::CoinbaseTransaction) {
    println!("unbox_coinbase_tx: {:?}", result);
    let ctx = unbox_any(result);
    println!("unbox_coinbase_tx.base: {:?}", ctx.base);
    unbox_tx(ctx.base);
    println!("unbox_coinbase_tx.merkle_root_mn_list: {:?}", ctx.merkle_root_mn_list);
    unbox_any(ctx.merkle_root_mn_list);
    println!("unbox_coinbase_tx.merkle_root_llmq_list: {:?}", ctx.merkle_root_llmq_list);
    if !ctx.merkle_root_llmq_list.is_null() {
        unbox_any(ctx.merkle_root_llmq_list);
    }
}

pub unsafe fn unbox_mn_list_diff_result(result: *mut types::MNListDiffResult) {
    println!("unbox_mn_list_diff_result: {:?}", result);
    let res = unbox_any(result);
    if res.error_status > 0 {
        return;
    }
    println!("unbox_mn_list_diff_result.base_block_hash: {:?}", res.base_block_hash);
    unbox_any(res.base_block_hash);
    println!("unbox_mn_list_diff_result.block_hash: {:?}", res.block_hash);
    unbox_any(res.block_hash);
    println!("unbox_mn_list_diff_result.masternode_list: {:?}", res.masternode_list);
    unbox_masternode_list(res.masternode_list);
    println!("unbox_mn_list_diff_result.needed_masternode_lists: {:?}", res.needed_masternode_lists);
    unbox_vec(unbox_vec_ptr(res.needed_masternode_lists, res.needed_masternode_lists_count));
    println!("unbox_mn_list_diff_result.added_masternodes: {:?}", res.added_masternodes);
    unbox_masternode_vec(unbox_vec_ptr(res.added_masternodes, res.added_masternodes_count));
    println!("unbox_mn_list_diff_result.modified_masternodes: {:?}", res.modified_masternodes);
    unbox_masternode_vec(unbox_vec_ptr(res.modified_masternodes, res.modified_masternodes_count));
    println!("unbox_mn_list_diff_result.added_llmq_type_maps: {:?}", res.added_llmq_type_maps);
    unbox_llmq_map_vec(unbox_vec_ptr(res.added_llmq_type_maps, res.added_llmq_type_maps_count));
}
pub unsafe fn unbox_mn_list_diff(result: *mut types::MNListDiff) {
    println!("unbox_mn_list_diff: {:?}", result);
    let list_diff = unbox_any(result);
    println!("unbox_mn_list_diff.base_block_hash: {:?}", list_diff.base_block_hash);
    unbox_any(list_diff.base_block_hash);
    println!("unbox_mn_list_diff.block_hash: {:?}", list_diff.block_hash);
    unbox_any(list_diff.block_hash);
    println!("unbox_mn_list_diff.merkle_hashes: {:?}", list_diff.merkle_hashes);
    // TODO: ???? hashes become *mut *mut [u8; 32] so...
    unbox_vec(unbox_vec_ptr(list_diff.merkle_hashes, list_diff.merkle_hashes_count));
    //unbox_any(std::ptr::slice_from_raw_parts_mut(list_diff.merkle_hashes, list_diff.merkle_hashes_count) as *mut [u8]);
    println!("unbox_mn_list_diff.merkle_flags: {:?}", list_diff.merkle_flags);
    unbox_any(std::ptr::slice_from_raw_parts_mut::<u8>(list_diff.merkle_flags, list_diff.merkle_flags_count));
    println!("unbox_mn_list_diff.coinbase_transaction: {:?}", list_diff.coinbase_transaction);
    unbox_coinbase_tx(list_diff.coinbase_transaction);
    println!("unbox_mn_list_diff.deleted_masternode_hashes: {:?}", list_diff.deleted_masternode_hashes);
    unbox_vec(unbox_vec_ptr(list_diff.deleted_masternode_hashes, list_diff.deleted_masternode_hashes_count));
    println!("unbox_mn_list_diff.added_or_modified_masternodes: {:?}", list_diff.added_or_modified_masternodes);
    unbox_masternode_vec(unbox_vec_ptr(list_diff.added_or_modified_masternodes, list_diff.added_or_modified_masternodes_count));
    println!("unbox_mn_list_diff.deleted_quorums: {:?}", list_diff.deleted_quorums);
    unbox_llmq_hash_vec(unbox_vec_ptr(list_diff.deleted_quorums, list_diff.deleted_quorums_count));
    println!("unbox_mn_list_diff.added_quorums: {:?}", list_diff.added_quorums);
    unbox_llmq_vec(unbox_vec_ptr(list_diff.added_quorums, list_diff.added_quorums_count));
}

pub unsafe fn unbox_qr_info(result: *mut types::QRInfo) {
    println!("unbox_qr_info: {:?}", result);
    let res = unbox_any(result);
    println!("unbox_qr_info.snapshot_at_h_c: {:?}", res.snapshot_at_h_c);
    unbox_llmq_snapshot(res.snapshot_at_h_c);
    println!("unbox_qr_info.snapshot_at_h_2c: {:?}", res.snapshot_at_h_2c);
    unbox_llmq_snapshot(res.snapshot_at_h_2c);
    println!("unbox_qr_info.snapshot_at_h_3c: {:?}", res.snapshot_at_h_3c);
    unbox_llmq_snapshot(res.snapshot_at_h_3c);
    println!("unbox_qr_info.mn_list_diff_tip: {:?}", res.mn_list_diff_tip);
    unbox_mn_list_diff(res.mn_list_diff_tip);
    println!("unbox_qr_info.mn_list_diff_at_h: {:?}", res.mn_list_diff_at_h);
    unbox_mn_list_diff(res.mn_list_diff_at_h);
    println!("unbox_qr_info.mn_list_diff_at_h_c: {:?}", res.mn_list_diff_at_h_c);
    unbox_mn_list_diff(res.mn_list_diff_at_h_c);
    println!("unbox_qr_info.mn_list_diff_at_h_2c: {:?}", res.mn_list_diff_at_h_2c);
    unbox_mn_list_diff(res.mn_list_diff_at_h_2c);
    println!("unbox_qr_info.mn_list_diff_at_h_3c: {:?}", res.mn_list_diff_at_h_3c);
    unbox_mn_list_diff(res.mn_list_diff_at_h_3c);
    if res.extra_share {
        println!("unbox_qr_info.snapshot_at_h_4c: {:?}", res.snapshot_at_h_4c);
        unbox_llmq_snapshot(res.snapshot_at_h_4c);
        println!("unbox_qr_info.mn_list_diff_at_h_4c: {:?}", res.mn_list_diff_at_h_4c);
        unbox_mn_list_diff(res.mn_list_diff_at_h_4c);
    }
    println!("unbox_qr_info.last_quorum_per_index: {:?}", res.last_quorum_per_index);
    unbox_vec(unbox_vec_ptr(res.last_quorum_per_index, res.last_quorum_per_index_count));
    println!("unbox_qr_info.quorum_snapshot_list: {:?}", res.quorum_snapshot_list);
    unbox_snapshot_vec(unbox_vec_ptr(res.quorum_snapshot_list, res.quorum_snapshot_list_count));
    println!("unbox_qr_info.mn_list_diff_list: {:?}", res.mn_list_diff_list);
    unbox_mn_list_diff_vec(unbox_vec_ptr(res.mn_list_diff_list, res.mn_list_diff_list_count));
}
pub unsafe fn unbox_qr_info_result(result: *mut types::QRInfoResult) {
    println!("unbox_qr_info_result: {:?}", result);
    let res = unbox_any(result);
    if res.error_status > 0 {
        return;
    }
    println!("unbox_qr_info_result.result_at_tip: {:?}", res.result_at_tip);
    unbox_mn_list_diff_result(res.result_at_tip);
    println!("unbox_qr_info_result.result_at_h: {:?}", res.result_at_h);
    unbox_mn_list_diff_result(res.result_at_h);
    println!("unbox_qr_info_result.result_at_h_c: {:?}", res.result_at_h_c);
    unbox_mn_list_diff_result(res.result_at_h_c);
    println!("unbox_qr_info_result.result_at_h_2c: {:?}", res.result_at_h_2c);
    unbox_mn_list_diff_result(res.result_at_h_2c);
    println!("unbox_qr_info_result.result_at_h_3c: {:?}", res.result_at_h_3c);
    unbox_mn_list_diff_result(res.result_at_h_3c);
    println!("unbox_qr_info_result.snapshot_at_h_c: {:?}", res.snapshot_at_h_c);
    unbox_llmq_snapshot(res.snapshot_at_h_c);
    println!("unbox_qr_info_result.snapshot_at_h_2c: {:?}", res.snapshot_at_h_2c);
    unbox_llmq_snapshot(res.snapshot_at_h_2c);
    println!("unbox_qr_info_result.snapshot_at_h_3c: {:?}", res.snapshot_at_h_3c);
    unbox_llmq_snapshot(res.snapshot_at_h_3c);
    if res.extra_share {
        println!("unbox_qr_info_result.result_at_h_4c: {:?}", res.result_at_h_4c);
        unbox_mn_list_diff_result(res.result_at_h_4c);
        println!("unbox_qr_info_result.snapshot_at_h_4c: {:?}", res.snapshot_at_h_4c);
        unbox_llmq_snapshot(res.snapshot_at_h_4c);
    }
    println!("unbox_qr_info_result.last_quorum_per_index: {:?}", res.last_quorum_per_index);
    unbox_llmq_vec(unbox_vec_ptr(res.last_quorum_per_index, res.last_quorum_per_index_count));
    println!("unbox_qr_info_result.quorum_snapshot_list: {:?}", res.quorum_snapshot_list);
    unbox_snapshot_vec(unbox_vec_ptr(res.quorum_snapshot_list, res.quorum_snapshot_list_count));
    println!("unbox_qr_info_result.mn_list_diff_list: {:?}", res.mn_list_diff_list);
    unbox_mn_list_diff_result_vec(unbox_vec_ptr(res.mn_list_diff_list, res.mn_list_diff_list_count));
}
