use rand::Rng;

pub fn calculate_y(x: u64, pol: &[u64]) -> u64 {
    pol.iter()
        .enumerate()
        .fold(0u64, |acc, (i, &p)| acc + p * x.pow(i as u32))
}

pub fn generate_pol(key: u64, k: u64) -> Vec<u64> {
    let mut rgn = rand::rng();
    let mut pol: Vec<u64> = vec![key];

    for _i in 1..k {
        pol.push(rgn.random());
    }

    pol
}

pub fn create_secret_shares(key: u64, k: u64, n: u64) -> &[u64] {}
