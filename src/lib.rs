use rug::{rand::RandState, Integer};

mod modular;

pub const BITS: u32 = 256;

pub fn calculate_biggest_prime(rnd: &mut RandState) -> Integer {
    loop {
        let candidate = Integer::from(Integer::random_bits(BITS, rnd));
        if candidate.is_probably_prime(30) != rug::integer::IsPrime::No {
            return candidate;
        }
    }
}

pub fn calculate_y(x: Integer, pol: &[Integer], prime: Integer) -> Integer {
    pol.iter().enumerate().fold(Integer::ZERO, |acc, (i, p)| {
        modular::add(
            acc,
            modular::mul(
                p.clone(),
                modular::pow(x.clone(), Integer::from(i.clone()), prime.clone()),
                prime.clone(),
            ),
            prime.clone(),
        )
    })
}

fn lagrange_pol(x: Integer, pol: &[(Integer, Integer)], prime: Integer) -> Integer {
    let n = pol.len();
    let mut result = Integer::from(0);

    for i in 0..n {
        let (xi, yi) = pol[i].clone();

        let mut num = Integer::from(1);
        let mut den = Integer::from(1);

        for j in 0..n {
            if j != i {
                let (xj, _) = pol[j].clone();
                num = modular::mul(
                    num.clone(),
                    modular::sub(
                        Integer::from(x.clone()),
                        Integer::from(xj.clone()),
                        prime.clone(),
                    ),
                    prime.clone(),
                );
                den = modular::mul(
                    den,
                    modular::sub(xi.clone(), xj, prime.clone()),
                    prime.clone(),
                );
            }
        }
        let div = modular::div(num, den, prime.clone());
        let term = modular::mul(yi, div, prime.clone());

        result = modular::add(result, term, prime.clone());
    }

    result
}

fn generate_unique(rnd: &mut RandState, v: &[Integer]) -> Integer {
    let r = Integer::from(Integer::random_bits(BITS, rnd));

    match v.iter().find(|&i| i == &r) {
        Some(_) => generate_unique(rnd, v),
        None => r,
    }
}

fn generate_pol(key: Integer, k: u64, rnd: &mut RandState) -> Vec<Integer> {
    let mut pol: Vec<Integer> = vec![key];

    for _i in 1..k {
        let r = generate_unique(rnd, &pol);
        pol.push(r);
    }

    pol
}

pub fn create_secret_shares(
    key: Integer,
    k: u64,
    n: u64,
    prime: Integer,
) -> Vec<(Integer, Integer)> {
    let mut rnd = RandState::new();

    let pol = generate_pol(key, k, &mut rnd);
    let mut shares: Vec<(Integer, Integer)> = Vec::new();
    let mut xs = Vec::new();

    for _i in 0..n {
        let x = generate_unique(&mut rnd, &xs);
        xs.push(x.clone());

        let y = calculate_y(x.clone(), &pol, prime.clone());
        shares.push((x.clone(), y));
    }

    shares
}

pub fn recover_secret(shares: &[(Integer, Integer)], prime: Integer) -> Integer {
    lagrange_pol(Integer::from(0), shares, prime)
}

#[test]
fn test_create_recover() {
    let mut rnd = RandState::new();

    let prime = calculate_biggest_prime(&mut rnd);

    let key = Integer::from(Integer::random_bits(BITS, &mut rnd)).modulo(&prime);
    let k = 10;
    let n = 15;

    let shares = create_secret_shares(key.clone(), k, n, prime.clone());
    let subset = &shares[0..(k as usize)];

    let recovered_key = recover_secret(subset, prime);

    assert_eq!(
        key, recovered_key,
        "Secret Shares: {:?} \n{key} compared to {recovered_key}\n",
        shares
    );
}
/*
#[test]
fn test_create_recover_bulk() {
    let mut handles = Vec::new();

    for _i in 0..100 {
        let handle = std::thread::spawn(|| {
            let mut rnd = RandState::new();
            let prime = calculate_biggest_prime(&mut rnd);

            for _i in 0..10000 {
                let key = Integer::from(Integer::random_bits(BITS, &mut rnd)).modulo(&prime);
                let k = 2;
                let n = 3;

                let shares = create_secret_shares(key.clone(), k, n, prime.clone());
                let subset = &shares[0..(k as usize)];

                let recovered_key = recover_secret(subset, prime.clone());

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
*/
