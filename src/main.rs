use frost_sig::keygen::keygen_ctx;
use frost_sig::{tcp::FrostSocketState, FrostState};
use rand::Rng;
use rug::{rand::RandState, Integer};

#[tokio::main]
async fn main() {
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    let ctx = keygen_ctx(Integer::from(1), Integer::from(1));
    let frost_state = FrostState::new(&mut rnd, 3, 2);

    let channel_state = FrostSocketState::new(frost_state, "localhost:3000".to_string());
    channel_state.serve_keygen(ctx).await.unwrap();
}
