use frost_sig::{
    tcp::{Address, Channel, Participant},
    FrostState,
};
use rand::Rng;
use rug::{rand::RandState, Integer};

#[tokio::main]
async fn main() {
    let seed: i32 = rand::rng().random();
    let mut rnd = RandState::new();
    rnd.seed(&rug::Integer::from(seed));

    let state = FrostState::init(&mut rnd, 5, 3);

    let mp = Participant::init(Integer::from(1), Address::Ip("localhost:3000".to_string()));
    let channel = Channel::init(state, mp).await.unwrap();
    channel.serve().await;
}
