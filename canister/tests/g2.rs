//! G2: derivation and release (docs/build-plan.md). The canister inside
//! PocketIC with real threshold keys: resolvers are stable and distinct, the
//! schedule law gates the signature, and every signature that leaves the
//! canister verifies against the derived resolver over the exact message the
//! deployed shape demands.

mod common;

use std::time::Duration;

use candid::Encode;
use ed25519_dalek::{Signature, VerifyingKey};
use serde_bytes::ByteBuf;
use subscription::api::{ReleaseArg, SignedRelease};

const DONOR: [u8; 32] = [0x11; 32];
const RECIPIENT: [u8; 32] = [0x22; 32];
const CHUNK: u64 = 1_000_000;
const N_CHUNKS: u16 = 12;
const PERIOD: i64 = 3_600;
const NONCE: u64 = 7;

fn release_arg(id: [u8; 32], t0: i64, index: u16) -> ReleaseArg {
    ReleaseArg {
        chain: common::CHAIN.to_string(),
        subscription_id: ByteBuf::from(id.to_vec()),
        donor: ByteBuf::from(DONOR.to_vec()),
        recipients: vec![ByteBuf::from(RECIPIENT.to_vec())],
        shares: vec![10_000],
        chunk: CHUNK,
        n_chunks: N_CHUNKS,
        t0,
        period: PERIOD,
        nonce: NONCE,
        index,
    }
}

fn request_release(
    pic: &pocket_ic::PocketIc,
    canister: candid::Principal,
    arg: &ReleaseArg,
) -> Result<SignedRelease, String> {
    let (result,): (Result<SignedRelease, String>,) = common::update(
        pic,
        canister,
        "request_release",
        Encode!(arg).expect("encodes"),
    );
    result
}

/// The escrow address the canister must derive: crown-salt over the birth
/// fields (resolver included), then the PDA arithmetic.
fn expected_escrow(resolver: &[u8], t0: i64) -> Vec<u8> {
    let resolver: [u8; 32] = resolver.try_into().expect("32 bytes");
    let salt = crown_salt::stream::salt(
        &DONOR,
        &[RECIPIENT],
        &[10_000],
        CHUNK,
        N_CHUNKS,
        t0,
        PERIOD,
        &resolver,
        NONCE,
    );
    let program: [u8; 32] = bs58::decode(common::FACTORY)
        .into_vec()
        .expect("bs58")
        .try_into()
        .expect("32 bytes");
    let (address, _bump) =
        crown_derive::solana_pda_address(program, &[b"escrow", &salt]).expect("pda exists");
    address.to_vec()
}

/// DOMAIN ‖ program ‖ escrow ‖ [0x00, index le] — the shape's release message.
fn release_message(escrow: &[u8], index: u16) -> Vec<u8> {
    let mut message = Vec::new();
    message.extend_from_slice(common::DOMAIN.as_bytes());
    message.extend_from_slice(&bs58::decode(common::FACTORY).into_vec().expect("bs58"));
    message.extend_from_slice(escrow);
    message.push(0x00);
    message.extend_from_slice(&index.to_le_bytes());
    message
}

fn verifies(resolver: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let key: [u8; 32] = match resolver.try_into() {
        Ok(key) => key,
        Err(_) => return false,
    };
    let signature: [u8; 64] = match signature.try_into() {
        Ok(signature) => signature,
        Err(_) => return false,
    };
    VerifyingKey::from_bytes(&key)
        .map(|key| {
            key.verify_strict(message, &Signature::from_bytes(&signature))
                .is_ok()
        })
        .unwrap_or(false)
}

#[test]
#[ignore]
fn resolvers_are_stable_and_distinct() {
    let (pic, canister) = common::setup();
    let a = common::resolver_of(&pic, canister, common::CHAIN, &[1u8; 32]).expect("resolver a");
    let b = common::resolver_of(&pic, canister, common::CHAIN, &[2u8; 32]).expect("resolver b");
    assert_eq!(a.len(), 32);
    assert_eq!(b.len(), 32);
    assert_ne!(a, b, "two subscriptions share a resolver");

    let again = common::resolver_of(&pic, canister, common::CHAIN, &[1u8; 32]).expect("resolver");
    assert_eq!(a, again, "resolver drifted between calls");
}

#[test]
#[ignore]
fn release_respects_the_schedule() {
    let (pic, canister) = common::setup();
    let id = [3u8; 32];
    let resolver = common::resolver_of(&pic, canister, common::CHAIN, &id).expect("resolver");

    // The stream starts an hour from now: chunk 0 is not due.
    let t0 = common::now_seconds(&pic) + 3_600;
    let arg = release_arg(id, t0, 0);
    let err = request_release(&pic, canister, &arg).expect_err("not due yet");
    assert!(err.contains("not due"), "unexpected error: {err}");

    // At t0 chunk 0 is due — inclusive boundary; chunk 1 is not.
    pic.advance_time(Duration::from_secs(3_700));
    let signed = request_release(&pic, canister, &arg).expect("due chunk signs");
    assert_eq!(signed.index, 0);
    assert_eq!(signed.escrow.as_slice(), expected_escrow(&resolver, t0));
    let message = release_message(&signed.escrow, 0);
    assert!(verifies(&resolver, &message, &signed.signature));

    let err = request_release(&pic, canister, &release_arg(id, t0, 1)).expect_err("chunk 1 early");
    assert!(err.contains("not due"), "unexpected error: {err}");

    // A period later chunk 1 matures; order among due chunks is the onchain
    // form's law, so the canister signs it without chunk 0 having executed.
    pic.advance_time(Duration::from_secs(PERIOD as u64));
    let signed = request_release(&pic, canister, &release_arg(id, t0, 1)).expect("chunk 1 due");
    let message = release_message(&signed.escrow, 1);
    assert!(verifies(&resolver, &message, &signed.signature));
}

#[test]
#[ignore]
fn signature_binds_subscription_and_index() {
    let (pic, canister) = common::setup();
    let id = [4u8; 32];
    let foreign = [5u8; 32];
    let resolver = common::resolver_of(&pic, canister, common::CHAIN, &id).expect("resolver");
    let foreign_resolver =
        common::resolver_of(&pic, canister, common::CHAIN, &foreign).expect("resolver");

    let t0 = common::now_seconds(&pic) - 10;
    let signed = request_release(&pic, canister, &release_arg(id, t0, 0)).expect("due");
    let message = release_message(&signed.escrow, 0);

    assert!(verifies(&resolver, &message, &signed.signature));
    // A foreign subscription's resolver rejects it.
    assert!(!verifies(&foreign_resolver, &message, &signed.signature));
    // The signature does not transfer to another chunk index.
    let other_index = release_message(&signed.escrow, 1);
    assert!(!verifies(&resolver, &other_index, &signed.signature));
}

#[test]
#[ignore]
fn retry_signs_the_same_message() {
    let (pic, canister) = common::setup();
    let id = [6u8; 32];
    let resolver = common::resolver_of(&pic, canister, common::CHAIN, &id).expect("resolver");

    let t0 = common::now_seconds(&pic) - 10;
    let first = request_release(&pic, canister, &release_arg(id, t0, 0)).expect("due");
    let second = request_release(&pic, canister, &release_arg(id, t0, 0)).expect("due again");

    // Nothing is stored: a retry re-derives the same escrow and returns an
    // equivalent valid signature over the same message.
    assert_eq!(first.escrow, second.escrow);
    let message = release_message(&first.escrow, 0);
    assert!(verifies(&resolver, &message, &first.signature));
    assert!(verifies(&resolver, &message, &second.signature));
}

#[test]
#[ignore]
fn malformed_requests_are_rejected() {
    let (pic, canister) = common::setup();
    let t0 = common::now_seconds(&pic) - 10;

    // Unknown chain.
    let mut arg = release_arg([7u8; 32], t0, 0);
    arg.chain = "solana-mainnet".to_string();
    let err = request_release(&pic, canister, &arg).expect_err("unknown chain");
    assert!(err.contains("unknown chain"), "unexpected error: {err}");
    let err = common::resolver_of(&pic, canister, "solana-mainnet", &[7u8; 32])
        .expect_err("unknown chain");
    assert!(err.contains("unknown chain"), "unexpected error: {err}");

    // subscription_id must be exactly 32 bytes.
    let mut arg = release_arg([7u8; 32], t0, 0);
    arg.subscription_id = ByteBuf::from(vec![7u8; 31]);
    let err = request_release(&pic, canister, &arg).expect_err("short id");
    assert!(err.contains("32 bytes"), "unexpected error: {err}");
    let err = common::resolver_of(&pic, canister, common::CHAIN, &[7u8; 31]).expect_err("short id");
    assert!(err.contains("32 bytes"), "unexpected error: {err}");

    // Birth fields must be 32-byte keys.
    let mut arg = release_arg([7u8; 32], t0, 0);
    arg.donor = ByteBuf::from(vec![0x11; 31]);
    let err = request_release(&pic, canister, &arg).expect_err("short donor");
    assert!(err.contains("bad field length"), "unexpected error: {err}");

    let mut arg = release_arg([7u8; 32], t0, 0);
    arg.recipients = vec![ByteBuf::from(vec![0x22; 33])];
    let err = request_release(&pic, canister, &arg).expect_err("long recipient");
    assert!(err.contains("bad field length"), "unexpected error: {err}");

    // A schedule whose due time leaves the clock's range is an error, not a
    // signature.
    let arg = release_arg([7u8; 32], i64::MAX - 1, 1);
    let err = request_release(&pic, canister, &arg).expect_err("overflow");
    assert!(err.contains("out of range"), "unexpected error: {err}");
}
