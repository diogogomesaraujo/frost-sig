use rand::{rngs::ThreadRng, Rng};

mod modular;

pub const RANGE: std::ops::Range<u64> = 0..3657500100;

pub const PRIME: u64 = 3657500101;

pub fn calculate_y(x: u64, pol: &[u64]) -> u64 {
    pol.iter().enumerate().fold(0, |acc, (i, &p)| {
        modular::add(
            acc,
            modular::mul(p, modular::pow(x, i as u64, PRIME), PRIME),
            PRIME,
        )
    })
}

fn lagrange_pol(x: u64, pol: &[(u64, u64)]) -> u64 {
    let n = pol.len();
    let mut result = 0;

    for i in 0..n {
        let (xi, yi) = pol[i];

        let mut num = 1;
        let mut den = 1;

        for j in 0..n {
            if j != i {
                let (xj, _) = pol[j];
                num = modular::mul(num, modular::sub(x, xj, PRIME), PRIME);
                den = modular::mul(den, modular::sub(xi, xj, PRIME), PRIME);
            }
        }
        let div = modular::div(num, den, PRIME);
        let term = modular::mul(yi, div, PRIME);

        result = modular::add(result, term, PRIME);
    }

    result
}

fn generate_unique(rgn: &mut ThreadRng, v: &[u64]) -> u64 {
    let r: u64 = rgn.random_range(RANGE);

    match v.contains(&r) || r == 0 {
        true => generate_unique(rgn, v),
        false => r,
    }
}

fn generate_pol(key: u64, k: u64, rgn: &mut ThreadRng) -> Vec<u64> {
    let mut pol: Vec<u64> = vec![key];

    for _i in 1..k {
        let r: u64 = generate_unique(rgn, &pol);
        pol.push(r);
    }

    pol
}

pub fn create_secret_shares(key: u64, k: u64, n: u64) -> Vec<(u64, u64)> {
    let mut rgn = rand::rng();

    let pol = generate_pol(key, k, &mut rgn);
    let mut shares: Vec<(u64, u64)> = Vec::new();
    let mut xs = Vec::new();

    for _i in 0..n {
        let x = generate_unique(&mut rgn, &xs);
        xs.push(x);

        let y = calculate_y(x, &pol);
        shares.push((x, y));
    }

    shares
}

pub fn recover_secret(shares: &[(u64, u64)]) -> u64 {
    lagrange_pol(0, shares)
}

#[test]
fn test_create_recover() {
    let mut handles = Vec::new();

    for _i in 0..5 {
        let handle = std::thread::spawn(|| {
            let mut rgn = rand::rng();

            for _i in 0..250000 {
                let key: u64 = rgn.random_range(RANGE);
                let k = 5;
                let n = 5;

                let shares = create_secret_shares(key, k, n);
                let subset = &shares[0..(k as usize)];

                let recovered_key = recover_secret(subset);

                assert_eq!(
                    key, recovered_key,
                    "Secret Shares: {:?} \n{key} compared to {recovered_key}\n",
                    shares
                );
            }
        });
        handles.push(handle);
    }

    for handle in handles {
        handle.join().unwrap();
    }
}
