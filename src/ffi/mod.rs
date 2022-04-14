use byte::{BytesExt, LE};
use dash_spv_primitives::crypto::byte_util::BytesDecodable;
use dash_spv_primitives::impl_bytes_decodable;
use crate::ffi::types::LLMQSnapshot;

pub mod boxer;
// pub mod from;
// pub mod to;
pub mod unboxer;
// pub mod wrapped_types;
pub mod types;


impl_bytes_decodable!(LLMQSnapshot);
