//! This crate contains all the functions to implement the FROST protocol.
//!
//! # frost-sig
//!
//! `frost-sig` is a threshold signature library that implements the FROST protocol.
//!
//! ## Features
//!
//! - Key Generation.
//! - Preprocessing.
//! - Signing Transactions.
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
//! ## Support
//!
//! See the [resources](https://eprint.iacr.org/2020/852.pdf) here.

use rug::{rand::RandState, Integer};

pub mod keygen;
pub mod preprocess;
pub mod sign;

pub mod modular;

pub mod message;

pub mod server;

#[cfg(test)]
pub mod test;

/// Const value of the Integers' size in bits.
pub const BITS: u32 = 256;

/// Const value for the serialization of numbers to base32 format.
pub const RADIX: i32 = 32;

/// Struct that saves the constants needed for FROST. These values should be used by all participants throughout the signing session and discarted after.
#[derive(Clone)]
pub struct FrostState {
    /// `prime` is a prime number bigger than any possible key or share generated and is used for modular arithmetic.
    pub prime: Integer,
    /// `q` is computed as `(prime - 1) / 2` and it is also used for modular arithmetic.
    pub q: Integer,
    /// `generator` is a constant value used for generating secret shares.
    pub generator: Integer,
    /// `participants` is the chosen number of participants that hold a secret share and can participate in signing operations.
    pub participants: u32,
    /// `threshold` is the minimum ammount of participants needed to sign a message.
    pub threshold: u32,
}

impl FrostState {
    /// Function that newializes the FrostState.
    pub fn new(rnd: &mut RandState, participants: u32, threshold: u32) -> Self {
        let (generated_prime, generated_q) = generate_prime_and_q(rnd);
        let generated_generator = generate_generator(rnd, &generated_q, &generated_prime);
        Self {
            prime: generated_prime,
            q: generated_q,
            generator: generated_generator,
            participants,
            threshold,
        }
    }
}

/// Struct that identifies the group, session and protocol being used.
#[derive(Clone, Debug)]
pub struct CTX {
    /// `protocol` is the name of the current protocol being used.
    pub protocol: String,
    /// `group_id` is the id of the group making the transaction
    pub group_id: Integer,
    /// `session_id` is the id of the current session.
    pub session_id: Integer,
}

impl CTX {
    /// Function that creates the CTX.
    pub fn new(protocol: &str, group_id: Integer, session_id: Integer) -> Self {
        Self {
            protocol: protocol.to_string(),
            group_id,
            session_id,
        }
    }

    /// Function that converts the `CTX` to `String`. It uses this format *protocol::group_id::session_id*.
    pub fn to_string(ctx: &CTX) -> String {
        format!("{}::{}::{}", ctx.protocol, ctx.group_id, ctx.session_id)
    }
}

/// Function that generates a random 256bit integer.
pub fn generate_integer(state: &FrostState, rnd: &mut RandState) -> Integer {
    Integer::from(Integer::random_below(state.q.clone(), rnd))
}

/// Function that generates a random `prime` and corresponding `q`.
pub fn generate_prime_and_q(rnd: &mut RandState) -> (Integer, Integer) {
    loop {
        let q_candidate = Integer::from(Integer::random_bits(BITS, rnd));
        let prime_candidate = Integer::from(2 * q_candidate.clone() + 1);
        match prime_candidate.is_probably_prime(30) {
            rug::integer::IsPrime::No => continue,
            _ => {
                return (prime_candidate, q_candidate);
            }
        }
    }
}

/// Function that generates a random `generator`.
pub fn generate_generator(rnd: &mut RandState, q: &Integer, prime: &Integer) -> Integer {
    loop {
        let prime_minus = Integer::from(prime.clone() - 1);
        let h = Integer::from(Integer::random_below(prime_minus.clone(), rnd));
        match h >= Integer::from(2) {
            true => {
                let g = modular::pow(&h, &modular::div(prime_minus, q.clone(), &prime), &prime);
                match g == Integer::from(1) {
                    true => continue,
                    _ => return g,
                }
            }
            _ => continue,
        }
    }
}
