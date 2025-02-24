use rand::{rngs::ThreadRng, Rng};
use std::{sync::Mutex, thread};

pub const RANGE: std::ops::Range<i64> = -100..100;

struct Ratio {
    dividend: i128,
    divisor: i128,
}

fn lcm_and_sum(a: Ratio, b: Ratio) -> Ratio {
    fn gcd(a: i128, b: i128) -> i128 {
        if b == 0 {
            a.abs()
        } else {
            gcd(b, a % b)
        }
    }

    fn lcm(a: i128, b: i128) -> i128 {
        (a.abs().wrapping_div(gcd(a, b))).wrapping_mul(b.abs())
    }

    let min_divisor = lcm(a.divisor, b.divisor);

    let factor_a = min_divisor.wrapping_div(a.divisor);
    let factor_b = min_divisor.wrapping_div(b.divisor);

    let result_dividend = a
        .dividend
        .wrapping_mul(factor_a)
        .wrapping_add(b.dividend.wrapping_mul(factor_b));

    Ratio {
        dividend: result_dividend,
        divisor: min_divisor,
    }
}

fn calculate_y(x: i64, pol: &[i64]) -> i64 {
    pol.iter().enumerate().fold(0, |acc, (i, &p)| {
        acc.wrapping_add(p.wrapping_mul(x.wrapping_pow(i as u32)))
    })
}

fn lagrange_pol(x: i64, pol: &[(i64, i64)]) -> i64 {
    let k = pol.len();
    let mut result: Ratio = Ratio {
        dividend: 0,
        divisor: 1,
    };

    for i in 0..k {
        let (xi, yi) = pol[i];

        let mut term: Ratio = Ratio {
            dividend: yi as i128,
            divisor: 1,
        };

        for j in 0..k {
            if j != i {
                let (xj, _) = pol[j];

                term.dividend = term.dividend.wrapping_mul((x - xj) as i128);
                term.divisor = term.divisor.wrapping_mul((xi - xj) as i128);
            }
        }
        result = lcm_and_sum(result, term);
    }

    result.dividend.wrapping_div(result.divisor) as i64
}

fn generate_unique(rgn: &mut ThreadRng, v: &[i64], range: std::ops::Range<i64>) -> i64 {
    let r: i64 = rgn.random_range(range.clone());

    match v.contains(&r) || r == 0 {
        true => generate_unique(rgn, v, range),
        false => r,
    }
}

fn generate_pol(key: i64, k: u64, rgn: &mut ThreadRng) -> Vec<i64> {
    let mut pol: Vec<i64> = vec![key];

    for _i in 1..k {
        let r: i64 = generate_unique(rgn, &pol, RANGE);
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
        let x = generate_unique(&mut rgn, &xs, RANGE);
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
        let handle = thread::spawn(|| {
            let mut rgn = rand::rng();

            for _i in 0..200000 {
                let key: i64 = rgn.random_range(RANGE);
                let k = 6;
                let n = 10;

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
