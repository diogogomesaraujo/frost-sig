//! This crate contains all the functions to implement threshold signature systems.
//!
//! # thresh-sig
//!
//! `thresh-sig` is a threshold signature library that implements threshold algorythms for 256bit integers.
//!
//! ## Features
//!
//! - Shamir Secret Sharing.
//! - Schnorr Threshold Signatures.
//! - Modular Arythmetic for `rug` integers.
//!
//! ## Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//! - `sha-256` is an implementation of SHA-256 and it is the predefined hashing algorythm for the threshold signature system.
//!
//! ## Requirements
//!
//! - Cargo installed
//!

pub mod modular;
pub mod schnorr;
pub mod shamir;

/// Const value of the Integers' size in bits.
pub const BITS: u32 = 256;

/// Const value of the Prime used for the operations as str.
pub const PRIME: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129640233";
