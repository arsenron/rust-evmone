// EVMC: Ethereum Client-VM Connector API.
// Copyright 2019 The EVMC Authors.
// Licensed under the Apache License, Version 2.0.

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

include!(concat!(env!("OUT_DIR"), "/bindings.rs"));

// Defining evmc_host_context here, because bindgen cannot create a useful declaration yet.

/// This is a void type given host context is an opaque pointer. Functions allow it to be a null ptr.
pub type evmc_host_context = ::std::os::raw::c_void;

impl From<[u8; 20]> for evmc_address {
    fn from(value: [u8; 20]) -> Self {
        Self { bytes: value }
    }
}

#[cfg(test)]
mod tests {
    use std::mem::size_of;

    use super::*;

    #[test]
    fn container_new() {
        // TODO: add other checks from test/unittests/test_helpers.cpp
        assert_eq!(size_of::<evmc_bytes32>(), 32);
        assert_eq!(size_of::<evmc_address>(), 20);
        assert!(size_of::<evmc_vm>() <= 64);
    }
}
