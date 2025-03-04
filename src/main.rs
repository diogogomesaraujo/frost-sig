use rug::rand::RandState;
use sss::*;

fn main() {
    let mut rnd = RandState::new();

    let prime = calculate_biggest_prime(&mut rnd);

    let key = generate_key(&mut rnd, &prime);
    let k = 10;
    let n = 15;

    let shares = create_secret_shares(key.clone(), k, n, &prime);
    let subset = &shares[0..(k as usize)];

    let recovered_key = recover_secret(subset, &prime);

    println!("Key: {key}\n\nRecovered Key: {recovered_key}");
}
