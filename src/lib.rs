//! This crate contains all the functions to implement threshold signature systems.

pub mod modular;
pub mod schnorr;
pub mod shamir;

/// Const value of the Integers' size in bits.
pub const BITS: u32 = 256;

/// Const value of the Prime used for the operations as str.
pub const PRIME: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129640233";
