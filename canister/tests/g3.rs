//! G3: the cancel authorization (docs/build-plan.md). Only the donor of the
//! declared birth fields can obtain an executable cancel; every binding of
//! the authorization message — signer, escrow, canister, cluster — is
//! checked against the real canister inside PocketIC.

mod common;

use candid::Encode;
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_bytes::ByteBuf;
use subscription::api::{CancelArg, SignedCancel};
use subscription::auth;

const RECIPIENT: [u8; 32] = [0x22; 32];
const CHUNK: u64 = 1_000_000;
const N_CHUNKS: u16 = 12;
const T0: i64 = 1_900_000_000;
const PERIOD: i64 = 3_600;
const NONCE: u64 = 7;

fn donor_key() -> SigningKey {
    SigningKey::from_bytes(&[9; 32])
}

fn cancel_arg(id: [u8; 32], donor: &[u8; 32], signature: Vec<u8>) -> CancelArg {
    CancelArg {
        chain: common::CHAIN.to_string(),
        subscription_id: ByteBuf::from(id.to_vec()),
        donor: ByteBuf::from(donor.to_vec()),
        recipients: vec![ByteBuf::from(RECIPIENT.to_vec())],
        shares: vec![10_000],
        chunk: CHUNK,
        n_chunks: N_CHUNKS,
        t0: T0,
        period: PERIOD,
        nonce: NONCE,
        signature: ByteBuf::from(signature),
    }
}

fn request_cancel(
    pic: &pocket_ic::PocketIc,
    canister: candid::Principal,
    arg: &CancelArg,
) -> Result<SignedCancel, String> {
    let (result,): (Result<SignedCancel, String>,) = common::update(
        pic,
        canister,
        "request_cancel",
        Encode!(arg).expect("encodes"),
    );
    result
}

/// The escrow the donor is cancelling, derived offchain exactly as the
/// canister derives it.
fn fee_wallet() -> [u8; 32] {
    bs58::decode(common::FEE_WALLET)
        .into_vec()
        .expect("bs58")
        .try_into()
        .expect("32 bytes")
}

fn escrow_of(resolver: &[u8], donor: &[u8; 32], nonce: u64) -> Vec<u8> {
    let resolver: [u8; 32] = resolver.try_into().expect("32 bytes");
    let salt = crown_salt::stream::salt(
        donor,
        &[RECIPIENT],
        &[10_000],
        CHUNK,
        N_CHUNKS,
        T0,
        PERIOD,
        &resolver,
        common::FEE_BPS,
        &fee_wallet(),
        nonce,
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
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn donor_cancel_is_signed() {
    let (pic, canister) = common::setup();
    let id = [1u8; 32];
    let resolver = common::resolver_of(&pic, canister, common::CHAIN, &id).expect("resolver");
    let key = donor_key();
    let donor = key.verifying_key().to_bytes();
    let escrow = escrow_of(&resolver, &donor, NONCE);

    let authorization = auth::cancel_authorization(common::CHAIN, &canister.to_text(), &escrow);
    let signature = key.sign(authorization.as_bytes()).to_bytes().to_vec();

    let signed =
        request_cancel(&pic, canister, &cancel_arg(id, &donor, signature)).expect("donor cancels");
    assert_eq!(signed.escrow.as_slice(), escrow);

    // The shape's cancel message, signed by this subscription's resolver.
    let mut message = Vec::new();
    message.extend_from_slice(common::DOMAIN.as_bytes());
    message.extend_from_slice(&bs58::decode(common::FACTORY).into_vec().expect("bs58"));
    message.extend_from_slice(&escrow);
    message.push(0x01);
    assert!(verifies(&resolver, &message, &signed.signature));

    // A replay of the same authorization returns an equivalent signature:
    // nothing is stored, terminality is onchain.
    let signature = key.sign(authorization.as_bytes()).to_bytes().to_vec();
    let again = request_cancel(&pic, canister, &cancel_arg(id, &donor, signature)).expect("replay");
    assert_eq!(again.escrow, signed.escrow);
    assert!(verifies(&resolver, &message, &again.signature));
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn foreign_signatures_are_rejected() {
    let (pic, canister) = common::setup();
    let id = [2u8; 32];
    let resolver = common::resolver_of(&pic, canister, common::CHAIN, &id).expect("resolver");
    let key = donor_key();
    let donor = key.verifying_key().to_bytes();
    let escrow = escrow_of(&resolver, &donor, NONCE);

    // A foreign wallet signs the right authorization: not the donor.
    let foreign = SigningKey::from_bytes(&[10; 32]);
    let authorization = auth::cancel_authorization(common::CHAIN, &canister.to_text(), &escrow);
    let signature = foreign.sign(authorization.as_bytes()).to_bytes().to_vec();
    let err = request_cancel(&pic, canister, &cancel_arg(id, &donor, signature))
        .expect_err("foreign signer");
    assert!(err.contains("bad signature"), "unexpected error: {err}");

    // The donor signs for a different escrow (another nonce): binding fails.
    let other_escrow = escrow_of(&resolver, &donor, NONCE + 1);
    let authorization =
        auth::cancel_authorization(common::CHAIN, &canister.to_text(), &other_escrow);
    let signature = key.sign(authorization.as_bytes()).to_bytes().to_vec();
    let err = request_cancel(&pic, canister, &cancel_arg(id, &donor, signature))
        .expect_err("foreign escrow");
    assert!(err.contains("bad signature"), "unexpected error: {err}");

    // The donor signs the escrow under a foreign canister id.
    let authorization = auth::cancel_authorization(common::CHAIN, "aaaaa-aa", &escrow);
    let signature = key.sign(authorization.as_bytes()).to_bytes().to_vec();
    let err = request_cancel(&pic, canister, &cancel_arg(id, &donor, signature))
        .expect_err("foreign canister");
    assert!(err.contains("bad signature"), "unexpected error: {err}");

    // The donor signs the escrow under a foreign cluster id.
    let authorization = auth::cancel_authorization("solana-mainnet", &canister.to_text(), &escrow);
    let signature = key.sign(authorization.as_bytes()).to_bytes().to_vec();
    let err = request_cancel(&pic, canister, &cancel_arg(id, &donor, signature))
        .expect_err("foreign cluster");
    assert!(err.contains("bad signature"), "unexpected error: {err}");
}

/// Cancel takes the same birth fields as release and must refuse the same
/// malformed ones — as values, not traps. A regression here either panics
/// the canister on an ingress call anyone can make, or spends a threshold
/// derivation on arguments that could never name an escrow.
#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn malformed_cancel_requests_are_rejected() {
    let (pic, canister) = common::setup();
    let id = [4u8; 32];
    let key = donor_key();
    let donor = key.verifying_key().to_bytes();
    let resolver = common::resolver_of(&pic, canister, common::CHAIN, &id).expect("resolver");
    let escrow = escrow_of(&resolver, &donor, NONCE);
    let authorization = auth::cancel_authorization(common::CHAIN, &canister.to_text(), &escrow);
    let signature = || key.sign(authorization.as_bytes()).to_bytes().to_vec();

    // Unknown chain: refused before the key derivation is paid for.
    let mut arg = cancel_arg(id, &donor, signature());
    arg.chain = "solana-mainnet".to_string();
    let err = request_cancel(&pic, canister, &arg).expect_err("unknown chain");
    assert!(err.contains("unknown chain"), "unexpected error: {err}");

    // subscription_id must be exactly 32 bytes: it is the derivation path.
    let mut arg = cancel_arg(id, &donor, signature());
    arg.subscription_id = ByteBuf::from(vec![4u8; 31]);
    let err = request_cancel(&pic, canister, &arg).expect_err("short id");
    assert!(err.contains("32 bytes"), "unexpected error: {err}");

    // A donor that is not a 32-byte key names no address and no verifier.
    let mut arg = cancel_arg(id, &donor, signature());
    arg.donor = ByteBuf::from(vec![0x11; 31]);
    let err = request_cancel(&pic, canister, &arg).expect_err("short donor");
    assert!(err.contains("bad field length"), "unexpected error: {err}");

    // Same for any recipient of the row.
    let mut arg = cancel_arg(id, &donor, signature());
    arg.recipients = vec![ByteBuf::from(vec![0x22; 33])];
    let err = request_cancel(&pic, canister, &arg).expect_err("long recipient");
    assert!(err.contains("bad field length"), "unexpected error: {err}");

    // A signature of the wrong size is a bad signature, not a panic.
    for len in [0usize, 63, 65] {
        let arg = cancel_arg(id, &donor, vec![7u8; len]);
        let err = request_cancel(&pic, canister, &arg).expect_err("bad signature length");
        assert!(err.contains("bad signature"), "unexpected error: {err}");
    }

    // The honest request still works: none of the above was rejected for an
    // unrelated reason.
    let signed = request_cancel(&pic, canister, &cancel_arg(id, &donor, signature()))
        .expect("donor cancels");
    assert_eq!(signed.escrow.as_slice(), escrow);
}

#[test]
#[ignore = "needs pocket-ic; run scripts/test-canister.sh"]
fn forged_donor_derives_a_foreign_escrow() {
    let (pic, canister) = common::setup();
    let id = [3u8; 32];
    let resolver = common::resolver_of(&pic, canister, common::CHAIN, &id).expect("resolver");

    // The victim's escrow is born with the victim's wallet as donor.
    let victim = donor_key().verifying_key().to_bytes();
    let victim_escrow = escrow_of(&resolver, &victim, NONCE);

    // An attacker declares the same birth fields but their own wallet as
    // donor and signs honestly with it. The canister signs — but for the
    // address those forged fields derive, where the victim's escrow does
    // not live. The victim's escrow never sees an executable cancel.
    let attacker = SigningKey::from_bytes(&[11; 32]);
    let attacker_donor = attacker.verifying_key().to_bytes();
    let attacker_escrow = escrow_of(&resolver, &attacker_donor, NONCE);
    let authorization =
        auth::cancel_authorization(common::CHAIN, &canister.to_text(), &attacker_escrow);
    let signature = attacker.sign(authorization.as_bytes()).to_bytes().to_vec();
    let signed = request_cancel(&pic, canister, &cancel_arg(id, &attacker_donor, signature))
        .expect("signs for the forged fields' own address");

    assert_ne!(signed.escrow.as_slice(), victim_escrow);
    assert_eq!(signed.escrow.as_slice(), attacker_escrow);
}
