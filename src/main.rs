use rug::rand::RandState;
use sss::*;
use std::time::Instant;

fn main() {
    let start = Instant::now();

    let mut rnd = RandState::new();
    let prime = calculate_biggest_prime(&mut rnd);

    let key = generate_key(&mut rnd, &prime);
    let k = 2;
    let n = 3;

    let shares = create_secret_shares(key.clone(), k, n, &prime);
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
