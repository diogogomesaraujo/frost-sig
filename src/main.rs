use frost_sig::{tcp::ChannelState, FrostState};
use rand::Rng;
use rug::rand::RandState;

#[tokio::main]
async fn main() {
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    // let ctx = keygen_ctx(Integer::from(1), Integer::from(1));
    let frost_state = FrostState::init(&mut rnd, 3, 2);

    let channel_state = ChannelState::new(frost_state, "localhost:3000".to_string());
    channel_state.serve().await.unwrap();
}
