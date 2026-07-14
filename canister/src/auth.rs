//! Escrow address arithmetic and config validation. Byte layouts here are a
//! frozen protocol; the unit tests pin them.
//!
//! The address is the proof (docs/game-spec.md §2, §7): the declared birth
//! fields are folded into the shape's salt by `crown-salt` and the address by
//! `crown-derive` — the same arithmetic the core's indexer uses. A wrong
//! declaration derives an address where no escrow will ever live; a signature
//! for it is harmless.

use crate::ChainSpec;

/// Domain separator of the donor's cancel authorization (docs/game-spec.md
/// §8). Versioned: a canister with different rules is a different game and
/// gets a different domain.
pub const DOMAIN: &[u8] = b"crown:subscription:v1";

/// The single action byte of the message protocol. Frozen forever.
pub const ACTION_CANCEL: u8 = 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuthError {
    UnknownChain,
    BadFieldLength,
    BadSignature,
    MalformedConfig,
    NoAddress,
}

impl AuthError {
    pub fn text(self) -> &'static str {
        match self {
            AuthError::UnknownChain => "unknown chain",
            AuthError::BadFieldLength => "bad field length",
            AuthError::BadSignature => "bad signature",
            AuthError::MalformedConfig => "malformed chain config",
            AuthError::NoAddress => "escrow address does not exist",
        }
    }
}

/// Length-prefixed part: u32 le length, then the bytes. Variable-length
/// parts are always framed so no two field splits share an encoding.
fn lp(out: &mut Vec<u8>, part: &[u8]) {
    out.extend((part.len() as u32).to_le_bytes());
    out.extend_from_slice(part);
}

/// The message the donor signs to authorize a cancel (docs/game-spec.md §8):
/// `DOMAIN ‖ lp(chain) ‖ lp(canister_id) ‖ lp(escrow) ‖ ACTION_CANCEL`.
/// Bound to the cluster, this canister and one escrow — it travels nowhere.
pub fn cancel_authorization(chain: &str, canister_id: &[u8], escrow: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(DOMAIN);
    lp(&mut out, chain.as_bytes());
    lp(&mut out, canister_id);
    lp(&mut out, escrow);
    out.push(ACTION_CANCEL);
    out
}

/// Verifies a wallet signature over `message` by `signer` — the wallet's
/// address bytes. Wallets sign the raw message with Ed25519 (64 bytes),
/// the address being the public key itself.
pub fn verify_wallet_signature(
    message: &[u8],
    signature: &[u8],
    signer: &[u8],
) -> Result<(), AuthError> {
    let signer: [u8; 32] = signer.try_into().map_err(|_| AuthError::BadFieldLength)?;
    let signature: [u8; 64] = signature.try_into().map_err(|_| AuthError::BadSignature)?;
    let key =
        ed25519_dalek::VerifyingKey::from_bytes(&signer).map_err(|_| AuthError::BadSignature)?;
    key.verify_strict(message, &ed25519_dalek::Signature::from_bytes(&signature))
        .map_err(|_| AuthError::BadSignature)
}

pub fn spec_of(chain: &str) -> Result<&'static ChainSpec, AuthError> {
    crate::CHAINS
        .iter()
        .find(|spec| spec.id == chain)
        .ok_or(AuthError::UnknownChain)
}

/// The escrow address of one subscription, derived from the declared birth
/// fields. `resolver` comes from the key derivation of the subscription_id,
/// never from the requester — a foreign resolver is underivable by
/// construction of the request.
#[allow(clippy::too_many_arguments)]
pub fn derive_escrow(
    spec: &ChainSpec,
    donor: &[u8],
    recipients: &[impl AsRef<[u8]>],
    shares: &[u16],
    chunk: u64,
    n_chunks: u16,
    t0: i64,
    period: i64,
    resolver: &[u8],
    nonce: u64,
) -> Result<Vec<u8>, AuthError> {
    let donor: [u8; 32] = donor.try_into().map_err(|_| AuthError::BadFieldLength)?;
    let resolver: [u8; 32] = resolver.try_into().map_err(|_| AuthError::BadFieldLength)?;
    let mut recipient_keys: Vec<[u8; 32]> = Vec::with_capacity(recipients.len());
    for recipient in recipients {
        recipient_keys.push(
            recipient
                .as_ref()
                .try_into()
                .map_err(|_| AuthError::BadFieldLength)?,
        );
    }
    // The shape owns its byte format: `crown-salt` is the single offchain
    // definition of the salt, parity-tested against the deployed program's
    // `birth_salt`.
    let salt = crown_salt::stream::salt(
        &donor,
        &recipient_keys,
        shares,
        chunk,
        n_chunks,
        t0,
        period,
        &resolver,
        nonce,
    );

    let program: [u8; 32] = bs58::decode(spec.factory)
        .into_vec()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(AuthError::MalformedConfig)?;
    let (address, _bump) = crown_derive::solana_pda_address(program, &[b"escrow", &salt])
        .ok_or(AuthError::NoAddress)?;
    Ok(address.to_vec())
}

/// Deploy-time validation: every baked chain entry must parse and the table
/// must be non-empty. Chains must be pairwise distinct in id, domain and
/// factory: the salt is chain-independent, so two entries sharing a
/// (factory, domain) would derive one escrow under two names.
pub fn validate_config() -> Result<(), AuthError> {
    if crate::CHAINS.is_empty() {
        return Err(AuthError::MalformedConfig);
    }
    for (i, spec) in crate::CHAINS.iter().enumerate() {
        bs58::decode(spec.factory)
            .into_vec()
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or(AuthError::MalformedConfig)?;
        if spec.domain.is_empty() {
            return Err(AuthError::MalformedConfig);
        }
        for other in crate::CHAINS.iter().skip(i.saturating_add(1)) {
            if spec.id == other.id || spec.domain == other.domain || spec.factory == other.factory {
                return Err(AuthError::MalformedConfig);
            }
        }
    }
    Ok(())
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

    fn spec() -> ChainSpec {
        ChainSpec {
            id: "solana-devnet",
            factory: "2pezd2u8LFMFULRzV2ygdRmH6BNxxU4AoeD8RSGgCdxv",
            domain: "crown:stream:solana-devnet",
        }
    }

    // The derivation is exactly salt (crown-salt, the pinned offchain
    // definition) followed by the PDA arithmetic (crown-derive, the core's
    // seam crate). Both are parity-tested against the chain in their own
    // repositories; this test pins the plumbing between them.
    #[test]
    fn escrow_is_salt_then_pda() {
        let donor = [0x11; 32];
        let recipients = [[0x22; 32]];
        let shares = [10_000u16];
        let resolver = [0x33; 32];
        let escrow = derive_escrow(
            &spec(),
            &donor,
            &recipients,
            &shares,
            1_000_000,
            12,
            1_900_000_000,
            2_592_000,
            &resolver,
            7,
        )
        .unwrap();

        let salt = crown_salt::stream::salt(
            &donor,
            &recipients,
            &shares,
            1_000_000,
            12,
            1_900_000_000,
            2_592_000,
            &resolver,
            7,
        );
        let program: [u8; 32] = bs58::decode(spec().factory)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let (expected, _) = crown_derive::solana_pda_address(program, &[b"escrow", &salt]).unwrap();
        assert_eq!(escrow, expected.to_vec());
    }

    #[test]
    fn escrow_derivation_rejects_bad_lengths() {
        let shares = [10_000u16];
        for (donor, recipient, resolver) in [
            (vec![0x11; 31], vec![0x22; 32], vec![0x33; 32]),
            (vec![0x11; 32], vec![0x22; 31], vec![0x33; 32]),
            (vec![0x11; 32], vec![0x22; 32], vec![0x33; 33]),
        ] {
            assert_eq!(
                derive_escrow(
                    &spec(),
                    &donor,
                    &[recipient],
                    &shares,
                    34,
                    1,
                    0,
                    1,
                    &resolver,
                    0
                ),
                Err(AuthError::BadFieldLength)
            );
        }
    }

    #[test]
    fn baked_config_is_valid() {
        validate_config().unwrap();
    }

    // ---- cancel authorization ----------------------------------------------

    #[test]
    fn cancel_authorization_layout_is_pinned() {
        let message = cancel_authorization("solana-devnet", &[0xAA, 0xBB], &[0xCC; 3]);
        let mut expected = Vec::new();
        expected.extend_from_slice(b"crown:subscription:v1");
        expected.extend(13u32.to_le_bytes());
        expected.extend_from_slice(b"solana-devnet");
        expected.extend(2u32.to_le_bytes());
        expected.extend_from_slice(&[0xAA, 0xBB]);
        expected.extend(3u32.to_le_bytes());
        expected.extend_from_slice(&[0xCC; 3]);
        expected.push(0);
        assert_eq!(message, expected);
        assert_eq!(ACTION_CANCEL, 0);
    }

    #[test]
    fn signature_roundtrip_and_rejections() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let address = key.verifying_key().to_bytes().to_vec();
        let message = cancel_authorization("solana-devnet", &[1], &[2; 32]);
        let sig = key.sign(&message).to_bytes().to_vec();
        verify_wallet_signature(&message, &sig, &address).unwrap();

        // Foreign signer.
        let other = ed25519_dalek::SigningKey::from_bytes(&[10; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        assert_eq!(
            verify_wallet_signature(&message, &sig, &other),
            Err(AuthError::BadSignature)
        );
        // Foreign escrow: same signer, different address.
        let foreign = cancel_authorization("solana-devnet", &[1], &[3; 32]);
        assert_eq!(
            verify_wallet_signature(&foreign, &sig, &address),
            Err(AuthError::BadSignature)
        );
        // Foreign canister: same escrow, different canister_id.
        let foreign = cancel_authorization("solana-devnet", &[2], &[2; 32]);
        assert_eq!(
            verify_wallet_signature(&foreign, &sig, &address),
            Err(AuthError::BadSignature)
        );
        // Foreign cluster: same everything, different chain id.
        let foreign = cancel_authorization("solana-mainnet", &[1], &[2; 32]);
        assert_eq!(
            verify_wallet_signature(&foreign, &sig, &address),
            Err(AuthError::BadSignature)
        );
    }
}
