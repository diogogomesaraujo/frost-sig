//! Implementation of FROST's pre-processing step.
//!
//! # Dependencies
//!
//! - `rug` is a arbitrary precision numbers crate and provides infrastructure for the 256bit numbers and calculations.
//! - `rand` is a random number generation crate and it is used to generate a random seed for the 256bit numbers generation.
//!
//! # Features
//!
//! - Generation of set of commitments and nonces.
//! - Multi-threaded generation of commitments and nonces on bulk.
//!
//! # Support
//!
//! - The keygen process should be executed everytime a participant's nonces and commitments stash gets empty.
//! - To learn more about the algorythms used for the pre-processing, bellow is a detailed explanation:
//!
//! **1.** Create an empty list Li. then, for 1 <= j <= Q, do the following：
//! - The single-use nonces sample (dij, eij) <-$- Zq* x Zq*
//! - Derive the commitment shares (Dij, Eij) = (g^{dij}^, g^{eij}^)
//! - Append (Dij, Eij) to Li. store ((dij, Dij), (eij, Eij)) for later use in signature operations
//!
//! **2.** Publish (i, Li) to a predefined location, specified by the implementer.
//!
//! See the [resources](https://eprint.iacr.org/2020/852.pdf) here.

use crate::*;

/// Function that generates a set of one-time-use nonces and commitments.
pub fn generate_nonces_and_commitments(
    state: &FrostState,
    rnd: &mut RandState,
) -> ((Integer, Integer), (Integer, Integer)) {
    let own_dij = generate_integer(&state, rnd);
    let own_eij = generate_integer(&state, rnd);
    let dij = modular::pow(&state.generator, &own_dij, &state.prime);
    let eij = modular::pow(&state.generator, &own_eij, &state.prime);
    ((own_dij, own_eij), (dij, eij))
}
