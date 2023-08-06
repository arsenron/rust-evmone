include!(concat!(env!("OUT_DIR"), "/bindings.rs")); // import `evmc_create_evmone()`

mod callbacks;

use bytes::Bytes;
use crypto_bigint::{Encoding, U256};
use evmc_sys::*;
use std::fmt::Debug;
use std::ptr::NonNull;
use std::slice;

pub type Address = [u8; 20];

pub type B32 = [u8; 32];

trait FromPtr {
    unsafe fn from_ptr(ptr: *const evmc_address) -> Self;
}

impl FromPtr for Address {
    unsafe fn from_ptr(ptr: *const evmc_address) -> Self {
        if ptr.is_null() {
            panic!("Got null pointer from evmone!");
        }

        (*ptr).bytes
    }
}

pub trait HostInterface: Sized {
    type Error: Debug;

    /// Checks if account exists under given address
    fn account_exists(&mut self, address: Address) -> Result<bool, Self::Error>;

    /// The storage value at the given storage key or None
    ///
    /// # Arguments
    ///
    /// * `key` - The index of the account's storage entry
    fn get_storage(&mut self, address: Address, key: U256) -> Result<U256, Self::Error>;

    /// Updates the given account storage entry. If `address` is not found,
    /// return `StorageStatus::Assigned`
    fn set_storage(
        &mut self,
        address: Address,
        key: U256,
        value: U256,
    ) -> Result<StorageStatus, Self::Error>;

    /// The balance of the given account or 0 if the account does not exist
    fn get_balance(&mut self, address: Address) -> Result<U256, Self::Error>;

    /// The code stored in the account at the given address.
    /// If there is no code under given `address`, implementor **MUST** return zero bytes
    fn get_code(&mut self, address: Address) -> Result<Bytes, Self::Error>;

    /// The address of the contract to be selfdestructed.
    ///
    /// *Returns* the information if the given address has not been registered as
    /// selfdestructed yet. True if registered for the first time, false otherwise.
    ///
    /// # Arguments
    ///
    /// * `beneficiary` - The address where the remaining ETH from `address` is going to be transferred
    ///
    fn selfdestruct(&mut self, address: Address, beneficiary: Address)
        -> Result<bool, Self::Error>;

    /// Main method used for calling underlying evm. See [Host](executor::host) implementation to understand
    /// how it can be implemented
    fn call(&mut self, message: Message) -> Result<EvmExecutionResult, Self::Error>;

    /// Block and transaction context
    fn get_tx_context(&mut self) -> VmTxContext;

    /// This callback function is used by a VM to query the hash of the header of the given block.
    /// If the information about the requested block is not available, then this is signalled by
    /// returning `None`
    ///
    /// # Arguments
    ///
    /// * `number` - The block number
    fn get_block_hash(&mut self, number: u64) -> Result<Option<B32>, Self::Error>;

    /// Inform about a LOG that happened during an EVM bytecode execution.
    ///
    /// # Arguments
    ///
    /// * `data` - Unindexed data, i.e. raw data attached to the log
    /// * `topics` - 32 byte arrays of topics. Length of the array cannot exceed 4
    ///              If there are no topics (anonymous events), `topics` equals `None`
    fn emit_log(
        &mut self,
        address: Address,
        data: &[u8],
        topics: Option<&[B32]>,
    ) -> Result<(), Self::Error>;

    /// If accrued substate A had this account before, i.e. {address} in Aa,
    /// return `AccessStatus::Warm`, else `AccessStatus::Cold`
    fn access_account(&mut self, address: Address) -> AccessStatus;

    /// If accrued substate A already accessed storage by `key` under given account,
    /// return `AccessStatus::Warm`, else `AccessStatus::Cold`
    fn access_storage(&mut self, address: Address, key: U256) -> AccessStatus;
}

trait HostContextExt: HostInterface {
    const EVMC_HOST_INTERFACE: evmc_host_interface = evmc_host_interface {
        account_exists: Some(callbacks::account_exists::<Self>),
        get_storage: Some(callbacks::get_storage::<Self>),
        set_storage: Some(callbacks::set_storage::<Self>),
        get_balance: Some(callbacks::get_balance::<Self>),
        get_code_size: Some(callbacks::get_code_size::<Self>),
        get_code_hash: Some(callbacks::get_code_hash::<Self>),
        copy_code: Some(callbacks::copy_code::<Self>),
        selfdestruct: Some(callbacks::selfdestruct::<Self>),
        call: Some(callbacks::call::<Self>),
        get_tx_context: Some(callbacks::get_tx_context::<Self>),
        get_block_hash: Some(callbacks::get_block_hash::<Self>),
        emit_log: Some(callbacks::emit_log::<Self>),
        access_account: Some(callbacks::access_account::<Self>),
        access_storage: Some(callbacks::access_storage::<Self>),
    };

    fn cast<'a>(evmc_host_context: *mut evmc_host_context) -> &'a mut Self {
        // SAFETY: We assume that `evmc_host_context` coming from evm is never NULL
        unsafe { &mut (*evmc_host_context.cast()) }
    }
}

impl<H> HostContextExt for H where H: HostInterface {}

pub struct Evm {
    inner: NonNull<evmc_vm>,
}

impl Evm {
    pub fn new() -> Self {
        unsafe {
            // SAFETY: we are promised that we always get valid evmc_vm instance
            Self {
                inner: NonNull::new(evmc_create_evmone()).unwrap(),
            }
        }
    }
}

impl Default for Evm {
    fn default() -> Self {
        Self::new()
    }
}

impl Evm {
    pub fn execute<H: HostInterface>(
        &mut self,
        host: &mut H,
        message: Message,
        code: &[u8],
        revision: Revision,
    ) -> EvmExecutionResult {
        let (code_ptr, code_size) = if code.is_empty() {
            (std::ptr::null(), 0)
        } else {
            (code.as_ptr(), code.len())
        };
        let evmc_message: evmc_message = (&message).into();
        unsafe {
            // SAFETY: See `new` constructor
            self.inner.as_mut().execute.unwrap()(
                self.inner.as_ptr(),
                &H::EVMC_HOST_INTERFACE,
                host as *mut H as *mut evmc_host_context,
                revision.into(),
                (&evmc_message) as *const _,
                code_ptr,
                code_size,
            )
        }
        .into()
    }
}

impl Drop for Evm {
    fn drop(&mut self) {
        unsafe {
            // SAFETY: destroy is a mandatory method and MUST NOT be set to NULL by evmone
            self.inner.as_ref().destroy.unwrap()(self.inner.as_ptr());
        }
    }
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Default)]
pub enum StorageStatus {
    #[default]
    Assigned = 0,
    Added = 1,
    Deleted = 2,
    Modified = 3,
    DeletedAdded = 4,
    ModifiedDeleted = 5,
    DeletedRestored = 6,
    AddedDeleted = 7,
    ModifiedRestored = 8,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum CallKind {
    /// Call to an account, either contract or EOA
    #[default]
    Call = 0,
    /// Valid since Homestead. The `value` param in [message](Message) is ignored
    DelegateCall = 1,
    CallCode = 2,
    Create = 3,
    /// Valid since Constantinople
    Create2 = 4,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum Revision {
    Frontier = 0,
    Homestead = 1,
    TangerineWhistle = 2,
    SpuriousDragon = 3,
    Byzantium = 4,
    Constantinople = 5,
    Petersburg = 6,
    Istanbul = 7,
    Berlin = 8,
    London = 9,
    Paris = 10,
    #[default]
    Shanghai = 11,
    Cancun = 12,
    Prague = 13,
}

/// Message passed to evm
#[derive(Debug, Clone)]
pub struct Message {
    pub kind: CallKind,
    /// If `true`, opcodes related to state modifications (such as SSTORE) will raise Evm exception
    pub is_static: bool,
    pub depth: u32,
    /// The amount of gas available to the message execution.
    pub gas_available: u64,
    pub recipient: Address,
    pub sender: Address,
    pub input_data: Option<Vec<u8>>,
    pub value: U256,
    /// is `Some` when `kind` is `Create2`
    pub create2_salt: Option<B32>,
    /// The account whose code is to be executed
    /// For [CallKind::CallCode] or [CallKind::DelegateCall] this may be different from
    /// `recepient`.
    ///
    /// Ignored if kind is `Create` or `Create2`
    pub code_address: Address,
}

impl Default for Message {
    fn default() -> Self {
        Self {
            kind: Default::default(),
            is_static: false,
            depth: 0,
            gas_available: i64::MAX as u64,
            recipient: Default::default(),
            sender: Default::default(),
            input_data: None,
            value: Default::default(),
            create2_salt: None,
            code_address: Default::default(),
        }
    }
}

impl Message {
    pub fn is_call(&self) -> bool {
        matches!(
            self.kind,
            CallKind::Call | CallKind::CallCode | CallKind::DelegateCall
        )
    }
}

impl From<&evmc_message> for Message {
    fn from(value: &evmc_message) -> Self {
        Message {
            kind: value.kind.into(),
            // When `flag` equals 1, it means we are in static mode
            is_static: value.flags == 1,
            depth: value.depth as u32,
            gas_available: value.gas as u64,
            recipient: Address::from(value.recipient.bytes),
            sender: Address::from(value.sender.bytes),
            input_data: if value.input_data.is_null() {
                None
            } else {
                // SAFETY: we assume pointer from evmone is valid.
                // We allocate a new vec because evmone will free this region of memory
                unsafe { Some(slice::from_raw_parts(value.input_data, value.input_size).to_vec()) }
            },
            value: U256::from_be_bytes(value.value.bytes),
            create2_salt: if value.create2_salt.bytes == [0; 32]
                || value.kind != evmc_call_kind::EVMC_CREATE2
            {
                None
            } else {
                Some(value.create2_salt.bytes)
            },
            code_address: Address::from(value.code_address.bytes),
        }
    }
}

impl From<&Message> for evmc_message {
    fn from(msg: &Message) -> Self {
        Self {
            kind: msg.kind.into(),
            flags: u32::from(msg.is_static),
            depth: msg.depth as i32,
            gas: msg.gas_available as i64,
            recipient: msg.recipient.into(),
            sender: msg.sender.into(),
            input_data: msg
                .input_data
                .as_ref()
                .map(|v| v.as_ptr())
                .unwrap_or(std::ptr::null()),
            input_size: msg.input_data.as_ref().map(|v| v.len()).unwrap_or(0),
            value: evmc_bytes32 {
                bytes: msg.value.to_be_bytes(),
            },
            create2_salt: evmc_bytes32 {
                bytes: msg.create2_salt.unwrap_or_default(),
            },
            code_address: msg.code_address.into(),
        }
    }
}

#[repr(i32)]
#[derive(Debug, Copy, Clone, PartialEq, Default)]
pub enum StatusCode {
    #[default]
    Success = 0,
    Failure = 1,
    Revert = 2,
    OutOfGas = 3,
    InvalidInstruction = 4,
    UndefinedInstruction = 5,
    StackOverflow = 6,
    StackUnderflow = 7,
    BadJumpDestination = 8,
    InvalidMemoryAccess = 9,
    CallDepthExceeded = 10,
    StaticModeViolation = 11,
    PrecompileFailure = 12,
    ContractValidationFailure = 13,
    ArgumentOutOfRange = 14,
    WasmUnreachableInstruction = 15,
    WasmTrap = 16,
    InsufficientBalance = 17,
    InternalError = -1,
    Rejected = -2,
    OutOfMemory = -3,
}

#[repr(u32)]
#[derive(Debug, Copy, Clone)]
pub enum AccessStatus {
    Cold = 0,
    Warm = 1,
}

#[derive(Debug, Clone, Default)]
pub struct EvmExecutionResult {
    pub status_code: StatusCode,
    pub gas_left: i64,
    /// The refunded gas accumulated from this execution and its sub-calls
    pub gas_refund: i64,
    pub output: Option<Vec<u8>>,
    pub create_address: Option<Address>,
}

impl EvmExecutionResult {
    pub fn failure() -> Self {
        EvmExecutionResult {
            status_code: StatusCode::Failure,
            ..Default::default()
        }
    }

    pub fn with_status(status_code: StatusCode) -> Self {
        Self {
            status_code,
            ..Default::default()
        }
    }

    pub fn is_success(&self) -> bool {
        matches!(self.status_code, StatusCode::Success)
    }
}

impl From<EvmExecutionResult> for evmc_result {
    fn from(value: EvmExecutionResult) -> Self {
        let (output_data, output_size) = if let Some(data) = value.output {
            let boxed = data.into_boxed_slice();
            let size = boxed.len();
            (Box::into_raw(boxed) as *const u8, size)
        } else {
            // avoid null pointers just to be a little more safer
            let boxed = Vec::<u8>::new().into_boxed_slice();
            (Box::into_raw(boxed) as *const u8, 0)
        };
        Self {
            output_data,
            output_size,
            status_code: value.status_code.into(),
            gas_left: value.gas_left,
            gas_refund: value.gas_refund,
            release: Some(release_result),
            create_address: evmc_address {
                bytes: value.create_address.unwrap_or_default(),
            },
            padding: [0u8; 4],
        }
    }
}

unsafe extern "C" fn release_result(ptr: *const evmc_result) {
    if ptr.is_null() {
        return;
    }
    let result = &*ptr;
    if !result.output_data.is_null() {
        // SAFETY: While creating evmc_result, we allocated output data on the heap
        // without using its destructor using `Box::into_raw` - so this is completely safe
        let _ = Box::from_raw(slice::from_raw_parts_mut(
            result.output_data as *mut u8,
            result.output_size,
        ));
    }
}

impl From<evmc_result> for EvmExecutionResult {
    fn from(evmc_result: evmc_result) -> Self {
        let status_code: StatusCode = evmc_result.status_code.into();
        if !matches!(status_code, StatusCode::Success) {
            tracing::warn!("EVM --- Transaction exited with status code: {status_code:?}");
        }
        // SAFETY: we MUST trust evmone that all invariants are held.
        // Note: We take a slice and then allocate a new vec for it because
        // evmone allocated memory and it MUST deallocate it
        // due to small possibility of using different allocators
        let output = (!evmc_result.output_data.is_null()).then(|| unsafe {
            let copied_slice =
                slice::from_raw_parts(evmc_result.output_data as *mut u8, evmc_result.output_size);
            copied_slice.to_vec()
        });
        let address_bytes = evmc_result.create_address.bytes;
        let create_address = if address_bytes.is_empty() {
            None
        } else {
            Some(address_bytes)
        };
        // Return value back to origin allocator
        if let Some(release_fn) = evmc_result.release {
            // SAFETY: we did not consume any of heap allocated resources of the `evmc_result`
            unsafe { release_fn(&evmc_result as *const _) }
        }
        Self {
            status_code,
            gas_left: evmc_result.gas_left,
            gas_refund: evmc_result.gas_refund,
            output,
            create_address,
        }
    }
}

#[derive(Debug, Clone)]
pub struct VmTxContext {
    pub gas_price: U256,
    pub origin: Address,
    /// The miner of the block
    pub block_coinbase: Address,
    pub block_number: i64,
    pub block_timestamp: i64,
    pub block_gas_limit: i64,
    /// previos RANDAO (EIP-4399)
    pub block_prev_randao: U256,
    pub chain_id: U256,
    /// The block base fee per gas (EIP-1559, EIP-3198)
    pub block_base_fee: U256,
}

impl Default for VmTxContext {
    fn default() -> Self {
        Self {
            gas_price: Default::default(),
            origin: Default::default(),
            block_coinbase: Default::default(),
            block_number: 0,
            block_timestamp: 0,
            block_gas_limit: i64::MAX,
            block_prev_randao: Default::default(),
            chain_id: U256::ONE,
            block_base_fee: Default::default(),
        }
    }
}

impl From<VmTxContext> for evmc_tx_context {
    fn from(ctx: VmTxContext) -> Self {
        Self {
            tx_gas_price: evmc_uint256be {
                bytes: ctx.gas_price.to_be_bytes(),
            },
            tx_origin: evmc_address { bytes: ctx.origin },
            block_coinbase: evmc_address {
                bytes: ctx.block_coinbase,
            },
            block_number: ctx.block_number,
            block_timestamp: ctx.block_timestamp,
            block_gas_limit: ctx.block_gas_limit,
            block_prev_randao: evmc_uint256be {
                bytes: ctx.block_prev_randao.to_be_bytes(),
            },
            chain_id: evmc_uint256be {
                bytes: ctx.chain_id.to_be_bytes(),
            },
            block_base_fee: evmc_uint256be {
                bytes: ctx.block_base_fee.to_be_bytes(),
            },
        }
    }
}

/// Implements From in two directions for enums
///
/// SAFETY: The caller MUST guarantee that enums have the same
/// discriminant representations as well as the same discriminants
/// in both enums.
macro_rules! convert_between_enums {
    ($($enum1:ty=$enum2:ty),+) => {
        $(
            impl From<$enum1> for $enum2 {
                fn from(value: $enum1) -> Self {
                    unsafe { std::mem::transmute(value) }
                }
            }

            impl From<$enum2> for $enum1 {
                fn from(value: $enum2) -> Self {
                    unsafe { std::mem::transmute(value) }
                }
            }
        )+
    }
}

convert_between_enums!(
    StorageStatus = evmc_storage_status,
    CallKind = evmc_call_kind,
    Revision = evmc_revision,
    StatusCode = evmc_status_code,
    AccessStatus = evmc_access_status
);

#[cfg(test)]
pub mod test_utils {
    use super::*;
    use std::collections::HashMap;

    #[derive(Debug, Default)]
    pub struct TestContext {
        pub topics: Option<Vec<B32>>,
        pub data: Vec<u8>,
        pub code: Vec<u8>,
        pub state: HashMap<Address, Vec<u8>>,
    }

    #[allow(unused)]
    /// Used to determine UB, can be removed in the future
    pub fn write_to_file(log: &str, file: &str) {
        use std::fs;
        use std::io::Write;
        let mut file = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(file)
            .unwrap();
        let mut owned = log.to_string();
        owned.push('\n');
        file.write_all(owned.as_bytes()).unwrap();
    }

    impl TestContext {
        pub fn new() -> Self {
            TestContext::default()
        }
        pub fn as_ptr(&mut self) -> *mut evmc_host_context {
            self as *mut _ as *mut _
        }
    }

    #[allow(unused_variables)]
    impl HostInterface for TestContext {
        type Error = Box<dyn std::error::Error>;

        fn account_exists(&mut self, address: Address) -> Result<bool, Self::Error> {
            Ok(true)
        }
        fn get_storage(&mut self, address: Address, key: U256) -> Result<U256, Self::Error> {
            Ok(U256::ZERO)
        }
        fn set_storage(
            &mut self,
            address: Address,
            key: U256,
            value: U256,
        ) -> Result<StorageStatus, Self::Error> {
            Ok(StorageStatus::Added)
        }
        fn get_balance(&mut self, address: Address) -> Result<U256, Self::Error> {
            Ok(U256::from_u128(1111111111111111111111))
        }
        fn get_code(&mut self, address: Address) -> Result<Bytes, Self::Error> {
            Ok(Bytes::from(self.code.clone()))
        }
        fn selfdestruct(
            &mut self,
            address: Address,
            beneficiary: Address,
        ) -> Result<bool, Self::Error> {
            Ok(self.state.remove(&address).is_some())
        }
        fn call(&mut self, message: Message) -> Result<EvmExecutionResult, Self::Error> {
            unimplemented!()
        }
        fn get_tx_context(&mut self) -> VmTxContext {
            VmTxContext::default()
        }
        fn get_block_hash(&mut self, number: u64) -> Result<Option<B32>, Self::Error> {
            unimplemented!()
        }
        fn emit_log(
            &mut self,
            address: Address,
            data: &[u8],
            topics: Option<&[B32]>,
        ) -> Result<(), Self::Error> {
            self.data = data.to_vec();
            self.topics = topics.map(|d| d.to_vec());
            Ok(())
        }

        fn access_account(&mut self, address: Address) -> AccessStatus {
            AccessStatus::Cold
        }

        fn access_storage(&mut self, address: Address, key: U256) -> AccessStatus {
            AccessStatus::Cold
        }
    }

    pub fn hex(hex_str: &str) -> Vec<u8> {
        let hex_str = if let Some(stripped) = hex_str.strip_prefix("0x") {
            stripped
        } else {
            hex_str
        };
        (0..hex_str.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&hex_str[i..i + 2], 16).unwrap())
            .collect()
    }

    /// If `C` > `hex_str` length, `hex_str` is filled from the right side,
    pub const fn hex_to_bytearray<const C: usize>(hex_str: &str) -> [u8; C] {
        if C == 0 {
            panic!("Size cannot be zero")
        };
        let bytes = hex_str.as_bytes();
        if !bytes.len() % 2 == 0 {
            panic!("Hex string must be even")
        }
        // todo: use str::get() when stabilized in const expressions
        let (hex_len, shift) = if bytes[0] == b'0' && bytes[1] == b'x' {
            // Shift hex string 2 characters right if it starts with '0x'
            ((bytes.len() - 2) / 2, 2)
        } else {
            (bytes.len() / 2, 0)
        };
        if C < hex_len {
            panic!("Array size cannot be smaller than hex array")
        }
        let mut buf = [0u8; C];
        let mut i = 0;
        while i < hex_len {
            buf[C - hex_len + i] =
                decode_hex_byte([bytes[2 * i + shift], bytes[2 * i + 1 + shift]]);
            i += 1
        }
        buf
    }

    pub const fn decode_hex_byte(hex: [u8; 2]) -> u8 {
        let mut out = 0u8;
        let mut i = 0;
        while i < 2 {
            out <<= 4;
            let byte = hex[i];
            let nibble = match byte {
                b'0'..=b'9' => byte - b'0',
                b'a'..=b'f' => byte + 10 - b'a',
                b'A'..=b'F' => byte + 10 - b'A',
                _ => panic!("Invalid hex string received"),
            };
            out |= nibble;
            i += 1
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::*;

    #[test]
    fn simple_opcodes() {
        let mut ctx = TestContext::new();
        let mut evm = Evm::new();
        let code = [0x60, 0x42, 0x60, 0xFF]; // Push 2 values on the stack, so we spend 6 Gas
        let message = Message {
            gas_available: 100,
            ..Default::default()
        };
        let res = evm.execute(&mut ctx, message, code.as_slice(), Default::default());
        assert_eq!(res.gas_left, 94) // See the "code" variable why we expect this
    }

    #[test]
    fn test_evmc_result_conversion() {
        unsafe {
            let execution_result = |data| EvmExecutionResult {
                status_code: StatusCode::Success,
                gas_left: 0,
                gas_refund: 0,
                output: data,
                create_address: None,
            };

            let mut data = Vec::with_capacity(33);
            data.extend_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8, 9]);
            let evmc_result: evmc_result = execution_result(Some(data)).into();
            let data = slice::from_raw_parts(evmc_result.output_data, evmc_result.output_size);
            assert_eq!(data, [1, 2, 3, 4, 5, 6, 7, 8, 9]);
            assert_eq!(evmc_result.output_size, 9);
            release_result(&evmc_result as *const evmc_result);

            let evmc_result: evmc_result = execution_result(None).into();
            let data = slice::from_raw_parts(evmc_result.output_data, evmc_result.output_size);
            assert!(data.is_empty());
            assert_eq!(evmc_result.output_size, 0);
            release_result(&evmc_result as *const evmc_result);

            let evmc_result: evmc_result = execution_result(Some(Vec::new())).into();
            let data = slice::from_raw_parts(evmc_result.output_data, evmc_result.output_size);
            assert!(data.is_empty());
            assert_eq!(evmc_result.output_size, 0);
            release_result(&evmc_result as *const evmc_result);
        }
    }

    #[test]
    fn selfdestruct_opcode() {
        let mut ctx = TestContext::new();
        // hex_to_bytearray("0xAA");
        let address = hex_to_bytearray("0xAA");
        ctx.state.insert(address, vec![1, 2, 3]);
        let mut evm = Evm::new();
        let res = evm.execute(
            &mut ctx,
            Message {
                gas_available: 100000,
                recipient: address,
                ..Default::default()
            },
            hex("60AAFF").as_slice(),
            Default::default(),
        );
        drop(evm);
        assert_eq!(res.status_code, StatusCode::Success);
        assert_eq!(ctx.state.get(&address), None);
    }

    #[test]
    fn test_output() {
        let mut ctx = TestContext::new();
        let sender = hex_to_bytearray("0xffff");
        let mut evm = Evm::new();
        // Copies 13 bytes of code (0D) to memory starting at 0x00 from 12-th byte of the contract
        // and then returns these 13 bytes from 0x00 (0xF3) code.
        // This means that we return output as all the code after 0xF3 instruction
        let code = hex("600D600C600039600D6000F3600260040160005360206000F3");
        let message = Message {
            kind: CallKind::Create,
            sender,
            gas_available: 100,
            create2_salt: None,
            value: U256::from_u32(100),
            input_data: None,
            ..Default::default()
        };
        let res = evm.execute(&mut ctx, message, code.as_slice(), Default::default());
        assert_eq!(res.status_code, StatusCode::Success);
        assert_eq!(
            res.output,
            // all the code after 0xF3 instruction
            Some(hex("600260040160005360206000F3"))
        );
    }

    #[test]
    fn test_enum_conversions() {
        assert_eq!(
            Into::<evmc_status_code>::into(StatusCode::InternalError),
            evmc_status_code::EVMC_INTERNAL_ERROR
        );

        assert_eq!(
            Into::<StatusCode>::into(evmc_status_code::EVMC_PRECOMPILE_FAILURE),
            StatusCode::PrecompileFailure
        );

        assert_eq!(
            Into::<evmc_storage_status>::into(StorageStatus::ModifiedRestored),
            evmc_storage_status::EVMC_STORAGE_MODIFIED_RESTORED
        );
    }
}
