use ca_core::{Error, Result};

/// Signature accepted by the hand-written ARM64 call stubs (no libffi).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AbiType {
    Void,
    Pointer,
    U32,
    I32,
    U64,
    I64,
    Float,
    Double,
}

/// A callable native function.  M2 generates the actual ARM64 stub.
#[derive(Clone, Debug)]
pub struct NativeFunction {
    pub address: usize,
    pub ret: AbiType,
    pub args: Vec<AbiType>,
}

impl NativeFunction {
    pub fn new(address: usize, ret: AbiType, args: Vec<AbiType>) -> Result<Self> {
        if address == 0 {
            return Err(Error::Parse("NativeFunction: null address".into()));
        }
        Ok(Self { address, ret, args })
    }

    pub fn call(&self, _args: &[u64]) -> Result<u64> {
        Err(Error::Unsupported("NativeFunction stub: M2"))
    }
}

/// Native callback created from a JS function.
pub struct NativeCallback {
    pub address: usize,
}

impl NativeCallback {
    pub fn new(_ret: AbiType, _args: Vec<AbiType>) -> Result<Self> {
        Err(Error::Unsupported("NativeCallback stub: M2"))
    }
}
