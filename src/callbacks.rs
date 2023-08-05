//! C callbacks that are expected by evmone

use crate::{EvmExecutionResult, HostContextExt};
use crate::{HostInterface, Message, B32};
use common::structures::address::Address;
use common::{keccak256, Logger, EMPTY_HASH};
use crypto_bigint::{Encoding, U256};
use evmc_sys::*;
use std::slice;

pub unsafe extern "C" fn account_exists<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
) -> bool {
    H::cast(context)
        .account_exists(Address::from_ptr(address))
        .log("HostInterface::account_exists error encountered")
        .unwrap_or_default()
}

pub unsafe extern "C" fn get_storage<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
    key: *const evmc_bytes32,
) -> evmc_bytes32 {
    evmc_bytes32 {
        bytes: H::cast(context)
            .get_storage(
                Address::from_ptr(address),
                U256::from_be_bytes((*key).bytes),
            )
            .log("HostInterface::get_storage error encountered")
            .unwrap_or_default()
            .to_be_bytes(),
    }
}

pub unsafe extern "C" fn set_storage<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
    key: *const evmc_bytes32,
    value: *const evmc_bytes32,
) -> evmc_storage_status {
    H::cast(context)
        .set_storage(
            Address::from_ptr(address),
            U256::from_be_bytes((*key).bytes),
            U256::from_be_bytes((*value).bytes),
        )
        .log("HostInterface::set_storage error encountered")
        .unwrap_or_default()
        .into()
}

pub unsafe extern "C" fn get_balance<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
) -> evmc_uint256be {
    evmc_uint256be {
        bytes: H::cast(context)
            .get_balance(Address::from_ptr(address))
            .log("HostInterface::get_balance error encountered")
            .unwrap_or_default()
            .to_be_bytes(),
    }
}

pub unsafe extern "C" fn get_code_size<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
) -> usize {
    H::cast(context)
        .get_code(Address::from_ptr(address))
        .log("HostInterface::get_code error encountered in get_code_size callback ")
        .unwrap_or_default()
        .len()
}

pub unsafe extern "C" fn get_code_hash<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
) -> evmc_bytes32 {
    let code = H::cast(context)
        .get_code(Address::from_ptr(address))
        .log("HostInterface::get_code error encountered in get_code_hash callback ")
        .unwrap_or_default();
    if code.is_empty() {
        return evmc_bytes32 { bytes: EMPTY_HASH };
    }
    evmc_bytes32 {
        bytes: keccak256(code).0,
    }
}

pub unsafe extern "C" fn copy_code<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
    code_offset: usize,
    buffer_data: *mut u8,
    buffer_size: usize,
) -> usize {
    let code = H::cast(context)
        .get_code(Address::from_ptr(address))
        .log("HostInterface::get_code error encountered in copy_code callback ")
        .unwrap_or_default();
    if code_offset >= code.len() || buffer_data.is_null() {
        return 0;
    }
    let bytes_to_copy = std::cmp::min(code.len() - code_offset, buffer_size);
    let code_slice_to_copy = &code[code_offset..(code_offset + bytes_to_copy)];
    // SAFETY: `buffer_data` is assumed to be valid for writes.
    // Also slices cannot overlap due to memory allocated separately
    buffer_data.copy_from_nonoverlapping(code_slice_to_copy.as_ptr(), bytes_to_copy);
    bytes_to_copy
}

pub unsafe extern "C" fn selfdestruct<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
    beneficiary: *const evmc_address,
) -> bool {
    H::cast(context)
        .selfdestruct(Address::from_ptr(address), Address::from_ptr(beneficiary))
        .log("HostInterface::selfdestruct error encountered")
        .unwrap_or_default()
}

pub unsafe extern "C" fn call<H: HostInterface>(
    context: *mut evmc_host_context,
    msg: *const evmc_message,
) -> evmc_result {
    let message: Message = (&*msg).into();
    let execution_result = H::cast(context)
        .call(message)
        .log("HostInterface::call error encountered")
        .unwrap_or_else(|_| EvmExecutionResult::failure());
    execution_result.into()
}

pub unsafe extern "C" fn get_tx_context<H: HostInterface>(
    context: *mut evmc_host_context,
) -> evmc_tx_context {
    H::cast(context).get_tx_context().into()
}

pub unsafe extern "C" fn get_block_hash<H: HostInterface>(
    context: *mut evmc_host_context,
    number: i64,
) -> evmc_bytes32 {
    evmc_bytes32 {
        bytes: H::cast(context)
            .get_block_hash(number as u64)
            .log("HostInterface::get_block_hash error encountered")
            .unwrap_or(None)
            .unwrap_or_default(),
    }
}

pub unsafe extern "C" fn emit_log<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
    data: *const u8,
    data_size: usize,
    topics: *const evmc_bytes32,
    topics_count: usize,
) {
    let data = if data.is_null() || data_size == 0 {
        &[]
    } else {
        slice::from_raw_parts(data, data_size)
    };
    let topics = if topics.is_null() || topics_count == 0 {
        None
    } else {
        Some(slice::from_raw_parts(topics as *const B32, topics_count))
    };
    H::cast(context)
        .emit_log(Address::from_ptr(address), data, topics)
        .log("HostInterface::emit_log error encountered")
        .ok();
}

pub unsafe extern "C" fn access_account<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
) -> evmc_access_status {
    H::cast(context)
        .access_account(Address::from_ptr(address))
        .into()
}

pub unsafe extern "C" fn access_storage<H: HostInterface>(
    context: *mut evmc_host_context,
    address: *const evmc_address,
    key: *const evmc_bytes32,
) -> evmc_access_status {
    H::cast(context)
        .access_storage(
            Address::from_ptr(address),
            U256::from_be_bytes((*key).bytes),
        )
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;
    use crate::B32;
    use common::{hex, hex_to_bytearray};
    use std::alloc::{alloc, dealloc, Layout};
    use std::{ptr, slice};

    #[allow(unused)]
    fn host_context_ptr() -> *mut evmc_host_context {
        &TestContext::EVMC_HOST_INTERFACE as *const _ as *mut _
    }

    #[test]
    fn test_emitting_logs() {
        unsafe {
            let mut ctx = TestContext::new();
            let address = evmc_address { bytes: [0; 20] };
            let data: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
            let topics: &[B32] = &[B32::default(), B32::default()];
            emit_log::<TestContext>(
                ctx.as_ptr(),
                &address as *const _,
                data.as_ptr(),
                data.len(),
                topics.as_ptr() as *const evmc_bytes32,
                topics.len(),
            );
            assert_eq!(ctx.topics, Some(topics.to_vec()));

            let data: &[u8] = &[1, 2, 3, 4, 5, 6, 7];
            let topics = ptr::null();
            emit_log::<TestContext>(
                ctx.as_ptr(),
                &address as *const _,
                data.as_ptr(),
                data.len(),
                topics as *const evmc_bytes32,
                0,
            );
            assert_eq!(ctx.topics, None);

            let layout = Layout::from_size_align(0, 1).unwrap();
            let data = ptr::null();
            let topics = alloc(layout);
            emit_log::<TestContext>(
                ctx.as_ptr(),
                &address as *const _,
                data as *const u8,
                0,
                topics as *const evmc_bytes32,
                0,
            );
            assert!(ctx.data.is_empty());
            assert_eq!(ctx.topics, None);
            dealloc(topics as *mut u8, layout);
        }
    }

    #[test]
    fn test_code_hash() {
        unsafe {
            let mut ctx = TestContext::new();
            ctx.code = hex("0xfa1287d2");
            let address = evmc_address { bytes: [0; 20] };
            let hash = get_code_hash::<TestContext>(ctx.as_ptr(), &address as *const _);
            assert_eq!(
                hash.bytes,
                hex_to_bytearray(
                    "3479ca1b1f9c881a81786a1e58f0c5cfade4d8f532e8bada85d02ccdd7e2bdb4"
                )
            );

            ctx.code = vec![];
            let hash = get_code_hash::<TestContext>(ctx.as_ptr(), &address as *const _);
            assert_eq!(hash.bytes, EMPTY_HASH)
        }
    }

    #[test]
    fn test_copy_code() {
        unsafe {
            const BUFFER_SIZE: usize = 3;
            let mut ctx = TestContext::new();
            ctx.code = vec![0, 1, 2, 3, 4, 5, 6, 7];
            let address = evmc_address { bytes: [0; 20] };
            let mut copy_code_lambda = |offset, ptr| {
                copy_code::<TestContext>(
                    ctx.as_ptr(),
                    &address as *const _,
                    offset,
                    ptr,
                    BUFFER_SIZE,
                )
            };
            let layout = Layout::new::<[u8; 3]>();

            let ptr = alloc(layout);
            let bytes_copied = copy_code_lambda(0, ptr);
            assert_eq!(bytes_copied, 3);
            assert_eq!(slice::from_raw_parts_mut(ptr, bytes_copied), [0, 1, 2]);
            dealloc(ptr, layout);

            let ptr = alloc(layout);
            let bytes_copied = copy_code_lambda(BUFFER_SIZE, ptr);
            assert_eq!(bytes_copied, 3);
            assert_eq!(slice::from_raw_parts_mut(ptr, bytes_copied), [3, 4, 5]);
            dealloc(ptr, layout);

            let ptr = alloc(layout);
            let bytes_copied = copy_code_lambda(BUFFER_SIZE * 2, ptr);
            assert_eq!(bytes_copied, 2);
            assert_eq!(slice::from_raw_parts_mut(ptr, bytes_copied,), [6, 7]);
            dealloc(ptr, layout);

            let ptr = alloc(layout);
            let bytes_copied = copy_code_lambda(BUFFER_SIZE * 3, ptr);
            assert_eq!(bytes_copied, 0);
            assert!(slice::from_raw_parts_mut(ptr, bytes_copied).is_empty());
            dealloc(ptr, layout);
        }
    }
}
