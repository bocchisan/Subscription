//! The threshold key tree (docs/game-spec.md §2, §7): every subscription_id
//! names its own resolver — the Ed25519 pubkey of this canister's threshold
//! key at derivation path [subscription_id] — and the on-demand signing uses
//! the same path. Nothing is stored; the private key exists nowhere.

use ic_cdk_management_canister::{
    SchnorrAlgorithm, SchnorrKeyId, SchnorrPublicKeyArgs, SignWithSchnorrArgs, schnorr_public_key,
    sign_with_schnorr,
};

/// The byte after the escrow address that marks a release; pinned to the
/// deployed shape's message framing (docs/game-spec.md §10).
pub const RELEASE_TAG: u8 = 0x00;
/// The byte after the escrow address that marks a cancel — same framing, so
/// the two verdict kinds can never drift apart.
pub const CANCEL_TAG: u8 = 0x01;

fn schnorr_key_id() -> SchnorrKeyId {
    SchnorrKeyId {
        algorithm: SchnorrAlgorithm::Ed25519,
        name: crate::THRESHOLD_KEY.to_string(),
    }
}

/// The RESOLVER birth field of every escrow of one subscription: the derived
/// pubkey at path [subscription_id]. Deterministic — clients cache it freely.
pub(crate) async fn resolver_key(subscription_id: &[u8; 32]) -> Result<Vec<u8>, String> {
    let result = schnorr_public_key(&SchnorrPublicKeyArgs {
        canister_id: None,
        derivation_path: vec![subscription_id.to_vec()],
        key_id: schnorr_key_id(),
    })
    .await
    .map_err(|error| format!("schnorr_public_key: {error}"))?;
    if result.public_key.len() != 32 {
        return Err("unexpected schnorr public key length".to_string());
    }
    Ok(result.public_key)
}

/// DOMAIN ‖ program ‖ escrow ‖ [RELEASE_TAG, index le] — the ed25519_program
/// message the escrow demands right before `release` (game-spec §10).
pub fn release_message(domain: &str, program: &[u8], escrow: &[u8], index: u16) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len().saturating_add(67));
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(program);
    message.extend_from_slice(escrow);
    message.push(RELEASE_TAG);
    message.extend_from_slice(&index.to_le_bytes());
    message
}

/// DOMAIN ‖ program ‖ escrow ‖ [CANCEL_TAG] — the ed25519_program message the
/// escrow demands right before `cancel` (game-spec §10).
pub fn cancel_message(domain: &str, program: &[u8], escrow: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(domain.len().saturating_add(65));
    message.extend_from_slice(domain.as_bytes());
    message.extend_from_slice(program);
    message.extend_from_slice(escrow);
    message.push(CANCEL_TAG);
    message
}

/// Signs a message with the subscription's derived key and sanity-checks the
/// result against the derived resolver: a signature the chain would reject
/// must never leave the canister.
pub(crate) async fn sign_for_subscription(
    subscription_id: &[u8],
    resolver: &[u8],
    message: &[u8],
) -> Result<Vec<u8>, String> {
    let result = sign_with_schnorr(&SignWithSchnorrArgs {
        message: message.to_vec(),
        derivation_path: vec![subscription_id.to_vec()],
        key_id: schnorr_key_id(),
        aux: None,
    })
    .await
    .map_err(|error| format!("sign_with_schnorr: {error}"))?;
    let key: [u8; 32] = resolver
        .try_into()
        .map_err(|_| "derived resolver is not 32 bytes")?;
    let signature: [u8; 64] = result
        .signature
        .as_slice()
        .try_into()
        .map_err(|_| "unexpected schnorr signature length")?;
    ed25519_dalek::VerifyingKey::from_bytes(&key)
        .and_then(|key| {
            key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        })
        .map_err(|_| "schnorr signature does not verify")?;
    Ok(signature.to_vec())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    // The release message mirrors the deployed shape byte for byte:
    // DOMAIN ‖ program_id ‖ escrow ‖ [0x00, index u16 LE].
    #[test]
    fn release_message_layout_is_pinned() {
        let message = release_message("crown:stream:solana-devnet", &[7; 32], &[9; 32], 258);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"crown:stream:solana-devnet");
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&[9; 32]);
        expected.push(0x00);
        expected.extend_from_slice(&[0x02, 0x01]);
        assert_eq!(message, expected);
        assert_eq!(RELEASE_TAG, 0x00);
    }

    // The cancel message shares the framing, with the cancel tag and no
    // parameters: DOMAIN ‖ program_id ‖ escrow ‖ [0x01].
    #[test]
    fn cancel_message_layout_is_pinned() {
        let message = cancel_message("crown:stream:solana-devnet", &[7; 32], &[9; 32]);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"crown:stream:solana-devnet");
        expected.extend_from_slice(&[7; 32]);
        expected.extend_from_slice(&[9; 32]);
        expected.push(0x01);
        assert_eq!(message, expected);
        assert_eq!(CANCEL_TAG, 0x01);
    }
}
