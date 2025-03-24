use rand::Rng;
use rug::{rand::RandState, Integer};
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
            "{}::{}::{}::{}::{}",
            shared_key.to_string_radix(16),
            reciever_address.to_string_radix(16),
            ammount,
            threshold,
            participants,
        )
    };

    let message = serialize_transaction_block(
        &shared_public_key,
        &Integer::from_str_radix(
            "38fe14d8c7191e6c3671b75cfb627b928a19ddeb16edf8dfff9336632315880a",
            16,
        )
        .unwrap(),
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

    let shares: Vec<String> = shares
        .iter()
        .map(|share| share.to_string_radix(16))
        .collect();
    let subset: Vec<String> = subset
        .iter()
        .map(|share| share.to_string_radix(16))
        .collect();
    let shared_public_key = shared_public_key.to_string_radix(16);

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
