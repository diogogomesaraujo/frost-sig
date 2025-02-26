use rand::{rngs::ThreadRng, Rng};

mod modular;

pub const RANGE: std::ops::Range<i64> = 0..6700416;

pub const PRIME: i64 = 6700417;

pub fn calculate_y(x: i64, pol: &[i64]) -> i64 {
    pol.iter().enumerate().fold(0, |acc, (i, &p)| {
        modular::add(
            acc,
            modular::mul(p, modular::pow(x, i as u64, PRIME), PRIME),
            PRIME,
        )
    })
}

fn lagrange_pol(x: i64, pol: &[(i64, i64)]) -> i64 {
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

fn generate_unique(rgn: &mut ThreadRng, v: &[i64]) -> i64 {
    let r: i64 = rgn.random_range(RANGE);

    match v.contains(&r) || r == 0 {
        true => generate_unique(rgn, v),
        false => r,
    }
}

fn generate_pol(key: i64, k: u64, rgn: &mut ThreadRng) -> Vec<i64> {
    let mut pol: Vec<i64> = vec![key];

    for _i in 1..k {
        let r: i64 = generate_unique(rgn, &pol);
        pol.push(r);
    }

    pol
}

pub fn create_secret_shares(key: i64, k: u64, n: u64) -> Vec<(i64, i64)> {
    let mut rgn = rand::rng();

    let pol = generate_pol(key, k, &mut rgn);
    let mut shares: Vec<(i64, i64)> = Vec::new();
    let mut xs = Vec::new();

    for _i in 0..n {
        let x = generate_unique(&mut rgn, &xs);
        xs.push(x);

        let y = calculate_y(x, &pol);
        shares.push((x, y));
    }

    shares
}

pub fn recover_secret(shares: &[(i64, i64)]) -> i64 {
    lagrange_pol(0, shares)
}

#[test]
fn test_create_recover() {
    let mut handles = Vec::new();

    for _i in 0..5 {
        let handle = std::thread::spawn(|| {
            let mut rgn = rand::rng();

            for _i in 0..250000 {
                let key: i64 = rgn.random_range(RANGE);
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
