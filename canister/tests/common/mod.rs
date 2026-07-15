//! Shared harness of the PocketIC integration tests: instance setup and
//! typed calls. The canister sits on the NNS subnet; the II subnet provides
//! the threshold keys.

#![allow(dead_code)] // each test binary uses its own subset

use candid::{Encode, Principal};
use pocket_ic::{PocketIc, PocketIcBuilder};
use serde_bytes::ByteBuf;

pub const CHAIN: &str = "solana-devnet";
/// Mirror of config/testnet.toml — the profile the test wasm is baked with.
/// The game's price tag from config/testnet.toml — part of every salt.
pub const FEE_BPS: u16 = 300;
pub const FEE_WALLET: &str = "3it64t7KXNip1C1BRYNh8ygeKyujWnaQrPSj3hV9TWbE";
pub const FACTORY: &str = "57MpCQ3TfAE66qDAnfkP9AX7LRqwd4CNX8uN6DaVwm3V";
pub const DOMAIN: &str = "crown:stream:solana-devnet";

pub fn game_wasm() -> Vec<u8> {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../target/wasm32-unknown-unknown/release/subscription.wasm"
    );
    std::fs::read(path).expect("wasm missing: run scripts/test-canister.sh")
}

pub fn setup() -> (PocketIc, Principal) {
    let pic = PocketIcBuilder::new()
        .with_nns_subnet()
        .with_ii_subnet()
        .build();
    let nns = pic.topology().get_nns().expect("nns subnet");
    let canister = pic.create_canister_on_subnet(None, None, nns);
    pic.add_cycles(canister, 10_000_000_000_000);
    pic.install_canister(canister, game_wasm(), Encode!().unwrap(), None);
    (pic, canister)
}

pub fn now_seconds(pic: &PocketIc) -> i64 {
    (pic.get_time().as_nanos_since_unix_epoch() / 1_000_000_000) as i64
}

pub fn update<R: for<'a> candid::utils::ArgumentDecoder<'a>>(
    pic: &PocketIc,
    canister: Principal,
    method: &str,
    arg: Vec<u8>,
) -> R {
    let reply = pic
        .update_call(canister, Principal::anonymous(), method, arg)
        .unwrap_or_else(|reject| panic!("{method} rejected: {reject:?}"));
    candid::utils::decode_args(&reply).expect("reply decodes")
}

pub fn resolver_of(
    pic: &PocketIc,
    canister: Principal,
    chain: &str,
    id: &[u8],
) -> Result<Vec<u8>, String> {
    let (result,): (Result<ByteBuf, String>,) = update(
        pic,
        canister,
        "get_resolver",
        Encode!(&chain.to_string(), &ByteBuf::from(id.to_vec())).unwrap(),
    );
    result.map(|key| key.to_vec())
}
