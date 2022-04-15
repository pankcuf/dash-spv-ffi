use std::collections::{BTreeMap, HashMap};
use std::slice;
use dash_spv_models::common::block_data::BlockData;
use dash_spv_models::common::llmq_type::LLMQType;
use dash_spv_models::common::socket_address::SocketAddress;
use dash_spv_models::masternode::{llmq_entry, masternode_entry, masternode_list};
use dash_spv_models::masternode::llmq_entry::LLMQ_DEFAULT_VERSION;
use dash_spv_models::tx::{coinbase_transaction, transaction};
use dash_spv_primitives::consensus::encode;
use dash_spv_primitives::crypto::byte_util::{Reversable, UInt128, UInt160, UInt256, UInt384, UInt768};
use crate::ffi;
use crate::ffi::to::ToFFI;

pub trait FromFFI<'a> {
    type Item: ToFFI<'a>;
    unsafe fn decode(&self) -> Self::Item;
}
impl<'a> FromFFI<'a> for ffi::types::TransactionInput {
    type Item = transaction::TransactionInput<'a>;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            input_hash: UInt256(*self.input_hash),
            index: self.index,
            script: if self.script.is_null() || self.script_length == 0 {
                None
            } else {
                Some(slice::from_raw_parts(self.script, self.script_length))
            },
            signature: if self.signature.is_null() || self.signature_length == 0 {
                None
            } else {
                Some(slice::from_raw_parts(self.signature, self.signature_length))
            },
            sequence: self.sequence
        }
    }
}

impl<'a> FromFFI<'a> for ffi::types::TransactionOutput {
    type Item = transaction::TransactionOutput<'a>;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            amount: self.amount,
            script: if self.script.is_null() || self.script_length == 0 {
                None
            } else {
                Some(slice::from_raw_parts(self.script, self.script_length))
            },
            address: if self.address.is_null() || self.address_length == 0 {
                None
            } else {
                Some(slice::from_raw_parts(self.address, self.address_length))
            }
        }
    }
}
impl<'a> FromFFI<'a> for ffi::types::Transaction {
    type Item = transaction::Transaction<'a>;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            inputs: (0..self.inputs_count)
                .into_iter()
                .map(|i| (*(*(self.inputs.offset(i as isize)))).decode())
                .collect(),
            outputs: (0..self.outputs_count)
                .into_iter()
                .map(|i| (*(*(self.outputs.offset(i as isize)))).decode())
                .collect(),
            lock_time: self.lock_time,
            version: self.version,
            tx_hash: None,
            tx_type: self.tx_type,
            payload_offset: self.payload_offset,
            block_height: self.block_height
        }
    }
}
impl<'a> FromFFI<'a> for ffi::types::CoinbaseTransaction {
    type Item = coinbase_transaction::CoinbaseTransaction<'a>;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            base: (*self.base).decode(),
            coinbase_transaction_version: self.coinbase_transaction_version,
            height: self.height,
            merkle_root_mn_list: UInt256(*self.merkle_root_mn_list),
            merkle_root_llmq_list: if self.merkle_root_llmq_list.is_null() { None } else { Some(UInt256(*self.merkle_root_llmq_list)) }
        }
    }
}

impl<'a> FromFFI<'a> for ffi::types::MasternodeList {
    type Item = masternode_list::MasternodeList<'a>;

    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            block_hash: UInt256(*self.block_hash),
            known_height: self.known_height,
            masternode_merkle_root: if self.masternode_merkle_root.is_null() { None } else { Some(UInt256(*self.masternode_merkle_root)) },
            llmq_merkle_root: if self.llmq_merkle_root.is_null() { None } else { Some(UInt256(*self.llmq_merkle_root)) },
            masternodes: (0..self.masternodes_count)
                .into_iter()
                .fold(BTreeMap::new(),|mut acc, i| {
                    let value = (*(*(self.masternodes.offset(i as isize)))).decode();
                    let key = value.provider_registration_transaction_hash.clone().reversed();
                    acc.insert(key, value);
                    acc
                }),
            quorums: (0..self.llmq_type_maps_count)
                .into_iter()
                .fold(HashMap::new(), |mut acc, i| {
                    let llmq_map = *(*(self.llmq_type_maps.offset(i as isize)));
                    let key = LLMQType::from(llmq_map.llmq_type);
                    let value: HashMap<UInt256, llmq_entry::LLMQEntry> =
                        (0..llmq_map.count)
                            .into_iter()
                            .fold(HashMap::new(), |mut acc, j| {
                                let raw_value = *(*(llmq_map.values.offset(j as isize)));
                                let value = raw_value.decode();
                                let key = value.llmq_hash.clone();
                                acc.insert(key, value);
                                acc
                            });
                    acc.insert(key, value);
                    acc
                })
        }
    }
}

impl<'a> FromFFI<'a> for ffi::types::MasternodeEntry {
    type Item = masternode_entry::MasternodeEntry;
    unsafe fn decode(&self) -> Self::Item {
        Self::Item {
            provider_registration_transaction_hash: UInt256(*self.provider_registration_transaction_hash),
            confirmed_hash: UInt256(*self.confirmed_hash),
            confirmed_hash_hashed_with_provider_registration_transaction_hash: if self.confirmed_hash_hashed_with_provider_registration_transaction_hash.is_null() { None } else { Some(UInt256(*self.confirmed_hash_hashed_with_provider_registration_transaction_hash)) },
            socket_address: SocketAddress { ip_address: UInt128(*self.ip_address), port: self.port },
            operator_public_key: UInt384(*self.operator_public_key),
            previous_operator_public_keys: (0..self.previous_operator_public_keys_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let obj = *self.previous_operator_public_keys.offset(i as isize);
                    let key = BlockData { height: obj.block_height, hash: UInt256(obj.block_hash) };
                    let value = UInt384(obj.key);
                    acc.insert(key, value);
                    acc
                }),
            previous_entry_hashes: (0..self.previous_entry_hashes_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let obj = *self.previous_entry_hashes.offset(i as isize);
                    let key = BlockData { height: obj.block_height, hash: UInt256(obj.block_hash) };
                    let value = UInt256(obj.hash);
                    acc.insert(key, value);
                    acc
                }),
            previous_validity: (0..self.previous_validity_count)
                .into_iter()
                .fold(BTreeMap::new(), |mut acc, i| {
                    let obj = *self.previous_validity.offset(i as isize);
                    let key = BlockData { height: obj.block_height, hash: UInt256(obj.block_hash) };
                    let value = obj.is_valid;
                    acc.insert(key, value);
                    acc
                }),
            known_confirmed_at_height: if self.known_confirmed_at_height > 0 { Some(self.known_confirmed_at_height) } else { None },
            update_height: self.update_height,
            key_id_voting: UInt160(*self.key_id_voting),
            is_valid: self.is_valid,
            entry_hash: UInt256(*self.entry_hash)
        }
    }
}

impl<'a> FromFFI<'a> for ffi::types::LLMQEntry {
    type Item = llmq_entry::LLMQEntry<'a>;

    unsafe fn decode(&self) -> Self::Item {
        let signers_bitset = slice::from_raw_parts(self.signers_bitset as *const u8, self.signers_bitset_length);
        let valid_members_bitset = slice::from_raw_parts(self.valid_members_bitset as *const u8, self.valid_members_bitset_length);
        Self::Item {
            version: self.version,
            llmq_hash: UInt256(*self.llmq_hash),
            index: if self.version == LLMQ_DEFAULT_VERSION { None } else { Some(self.index) },
            public_key: UInt384(*self.public_key),
            threshold_signature: UInt768(*self.threshold_signature),
            verification_vector_hash: UInt256(*self.verification_vector_hash),
            all_commitment_aggregated_signature: UInt768(*self.all_commitment_aggregated_signature),
            signers_count: encode::VarInt(self.signers_count),
            llmq_type: self.llmq_type,
            valid_members_count: encode::VarInt(self.valid_members_count),
            signers_bitset,
            valid_members_bitset,
            length: self.length,
            entry_hash: UInt256(*self.entry_hash),
            verified: self.verified,
            saved: self.saved,
            commitment_hash: if self.commitment_hash.is_null() { None } else { Some(UInt256(*self.commitment_hash)) }
        }
    }
}