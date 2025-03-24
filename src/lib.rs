//! This crate contains all the functions to implement threshold signature systems.

use rug::{rand::RandState, Integer};
use std::str::FromStr;

pub mod keygen;
pub mod modular;
pub mod preprocess;
pub mod shamir;

/// Const value of the Integers' size in bits.
pub const BITS: u32 = 256;

/// Const value of the Prime used for the operations as str.
pub const PRIME: &str =
    "115792089237316195423570985008687907853269984665640564039457584007913129640233";

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
    pub participants: usize,
    /// `threshold` is the minimum ammount of participants needed to sign a message.
    pub threshold: usize,
}

impl FrostState {
    /// Function that initializes the FrostState.
    ///
    /// ## Parameters
    ///
    /// - `p` is the number of participants.
    /// - `t` is the threshold.
    ///
    /// They will determine how many shares are generated and the minimum used for signing operations.
    /// The rest of the parameters are initialized internally.
    ///
    /// ## Returns
    ///
    /// - `FrostState` initialized with the participants and threshold defined.
    pub fn init(participants_input: usize, threshold_input: usize) -> Self {
        Self {
            prime: Integer::from_str(PRIME).expect("Shouldn't happen."),
            q: Integer::from((Integer::from_str(PRIME).expect("Shouldn't happen.") - 1) / 2),
            generator: Integer::from(4),
            participants: participants_input,
            threshold: threshold_input,
        }
    }
}

// Struct that identifies the group, session and protocol being used.
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
    /// Function that initializes the CTX.
    ///
    /// ## Parameters
    ///
    /// - `protocol` is the step of FROST currently being used.
    /// - `group_id` is the id of the group.
    /// - `session_id` is the id of the current session (each transaction should have it's own section).
    ///
    ///
    /// ## Returns
    ///
    /// - `CTX` initialized with the information of the session, group and protocol.
    pub fn init(protocol: &str, group_id_input: Integer, session_id_input: Integer) -> Self {
        Self {
            protocol: protocol.to_string(),
            group_id: group_id_input,
            session_id: session_id_input,
        }
    }

    /// Function that serializes the CTX.
    ///
    /// ## Parameters
    ///
    /// - `ctx` is the CTX being serialized.
    ///
    ///
    /// ## Returns
    ///
    /// - `String` that is the ctx with the parameters separated by "::".
    pub fn to_string(ctx: &CTX) -> String {
        format!("{}::{}::{}", ctx.protocol, ctx.group_id, ctx.session_id)
    }
}

/// Function that generates a random 256bit integer.
///
/// ## Parameters
///
/// - `state` is has the constants needed for FROST.
/// - `rnd` is the state for generating random 256bit numbers.
///
///
/// ## Returns
///
/// - `Integer` that is generated.
pub fn generate_integer(state: &FrostState, rnd: &mut RandState) -> Integer {
    Integer::from(Integer::random_below(state.q.clone(), rnd))
}
