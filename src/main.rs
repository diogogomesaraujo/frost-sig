use rand::Rng;
use rug::rand::RandState;

#[tokio::main]
async fn main() {
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    frost_sig::server::keygen::run("localhost", 3333, 3, 2)
        .await
        .unwrap();
}
