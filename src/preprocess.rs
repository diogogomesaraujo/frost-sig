use crate::*;

pub fn generate_nonces_and_commitments(
    state: &FrostState,
    rnd: &mut RandState,
) -> ((Integer, Integer), (Integer, Integer)) {
    let dij = generate_integer(&state, rnd);
    let eij = generate_integer(&state, rnd);
    let cdij = modular::pow(&state.generator, &dij, &state.q);
    let ceij = modular::pow(&state.generator, &eij, &state.q);
    ((dij, eij), (cdij, ceij))
}
