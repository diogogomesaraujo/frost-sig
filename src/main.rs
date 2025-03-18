use rand::Rng;
use rug::{rand::RandState, Integer};
use schnorr::*;
use shamir::*;
use std::{str::FromStr, time::Instant};
use thresh_sig::*;

fn main() {
    let start = Instant::now();

    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    let state = SchnorrThresholdState::init(10, 5);

    let shares = generate_secret_shares(&state, &mut rnd);
    let subset = &shares[0..(state.threshold)];

    let shared_public_key = generate_shared_key(&state, subset);

    let serialize_transaction_block = |shared_key: &Integer,
                                       reciever_address: &Integer,
                                       ammount: &f64,
                                       threshold: &usize,
                                       participants: &usize| {
        format!(
            "{}:{}:{}:{}:{}",
            shared_key, reciever_address, ammount, threshold, participants,
        )
    };

    let message = serialize_transaction_block(
        &shared_public_key,
        &Integer::from(1),
        &2.4,
        &state.threshold,
        &state.participants,
    );

    let (shared_commitment, signature_response) = sign(&state, &mut rnd, &message, subset);

    let result = verify(
        &state,
        &message,
        &shared_commitment,
        &signature_response,
        &shared_public_key,
    );

    println!(
        "
        Shared Public Key: {:?}\n
        Shares:            {:?}\n
        Subset:            {:?}\n
        Message:           {}\n
        Validation:        {}\n",
        shared_public_key, shares, subset, message, result
    );

    println!("The program took {:?} to run.", start.elapsed());
}

/*
fn main() {
    let start = Instant::now();

    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    let prime = Integer::from_str(PRIME).expect("Shouldn't happen.");

    let key = generate_key(&mut rnd, &prime);
    let k = 7;
    let n = 10;

    let shares = create_secret_shares(key.clone(), k, n, &prime, &mut rnd);
    let subset = &shares[0..(k as usize)];

    let recovered_key = recover_secret(subset, &prime);

    assert_eq!(
        key, recovered_key,
        "Secret Shares: {:?} \n{key} compared to {recovered_key}\n",
        shares
    );

    println!(
        "The generated key was {key} and the recovered key from the shares was {recovered_key}",
        key = key.to_string_radix(16),
        recovered_key = recovered_key.to_string_radix(16)
    );

    println!("The program took {:?} to run.", start.elapsed());
}
*/
