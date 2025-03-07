//! This crate contains all the functions to generate and share secret keys. The secret keys' bit size is defaulted to 256.

pub mod frost;
pub mod modular;
pub mod sss;

/// Const value of the Integers' size in bits.
pub const BITS: u32 = 256;
pub const PRIME: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129640233";
