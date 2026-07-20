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
pub const DOMAIN: &str = "crown:subscription:v1";

/// The single action this protocol has, as the message spells it. Frozen.
pub const ACTION_CANCEL: &str = "cancel";

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

/// The message the donor signs to authorize a cancel (docs/game-spec.md §8):
/// One field per line, `key: value`:
///
/// ```text
/// crown:subscription:v1
/// action: cancel
/// chain: solana-devnet
/// canister: vg3po-ix777-77774-qaafa-cai
/// escrow: CS1mmfBkPLimY6WLGczafmQBiQNUKTUmQrCfDBKUJEyz
/// ```
///
/// **Text, because wallets refuse to sign anything else.** Phantom runs
/// `isValidUTF8` over the payload and rejects the rest with "You cannot sign
/// solana transactions using sign message" — a binary layout here would
/// make cancelling impossible with the largest Solana wallet. A donor should
/// be able to read what they are cancelling: the escrow address here is the
/// same base58 an explorer shows.
///
/// Injective: fixed, ordered keys; the address is base58 and the chain id is
/// checked by `validate_config`, so no value can carry a newline.
pub fn cancel_authorization(chain: &str, canister_id: &str, escrow: &[u8]) -> String {
    format!(
        "{DOMAIN}\n\
         action: cancel\n\
         chain: {chain}\n\
         canister: {canister_id}\n\
         escrow: {}\n",
        bs58::encode(escrow).into_string()
    )
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
    // The game's fee is part of the salt and comes from the config, never
    // from the requester: an escrow born with a price other than this
    // game's derives a different address and never gets a signature.
    let fee_wallet: [u8; 32] = bs58::decode(spec.fee_wallet)
        .into_vec()
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or(AuthError::MalformedConfig)?;
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
        spec.fee_bps,
        &fee_wallet,
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
    validate_chains(crate::CHAINS)
}

/// The rule itself, over an explicit table: the baked one in production, a
/// crafted one in the tests that pin each rejection.
fn validate_chains(chains: &[ChainSpec]) -> Result<(), AuthError> {
    if chains.is_empty() {
        return Err(AuthError::MalformedConfig);
    }
    for (i, spec) in chains.iter().enumerate() {
        bs58::decode(spec.factory)
            .into_vec()
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or(AuthError::MalformedConfig)?;
        bs58::decode(spec.fee_wallet)
            .into_vec()
            .ok()
            .filter(|b| b.len() == 32)
            .ok_or(AuthError::MalformedConfig)?;
        if spec.fee_bps >= 10_000 {
            return Err(AuthError::MalformedConfig);
        }
        if spec.domain.is_empty() {
            return Err(AuthError::MalformedConfig);
        }
        for other in chains.iter().skip(i.saturating_add(1)) {
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

    const CANISTER: &str = "vg3po-ix777-77774-qaafa-cai";
    /// base58 of [0xCC; 32], computed independently with python.
    const ESCROW_B58: &str = "EnTJCS15dqbDTU2XywYSMaScoPv4Py4GzExrtY9DQxoD";

    fn spec() -> ChainSpec {
        ChainSpec {
            id: "solana-devnet",
            factory: "57MpCQ3TfAE66qDAnfkP9AX7LRqwd4CNX8uN6DaVwm3V",
            domain: "crown:stream:solana-devnet",
            fee_bps: 500,
            // base58 of [0x44; 32].
            fee_wallet: "5bV6jUfhDHCQVA1WfKBUnXUsboJgoKgkzkKcxr3joew5",
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
            500,
            &[0x44; 32],
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

    /// K > 1 is the ordinary case of a stream split between several
    /// recipients. If the loop over recipients ever stopped folding all of
    /// them (or their order) into the salt, two different splits would share
    /// one address and one signature.
    #[test]
    fn escrow_is_salt_then_pda_with_several_recipients() {
        let donor = [0x11; 32];
        let recipients = [[0x22; 32], [0x23; 32], [0x24; 32]];
        let shares = [5_000u16, 3_000, 2_000];
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
            500,
            &[0x44; 32],
            7,
        );
        let program: [u8; 32] = bs58::decode(spec().factory)
            .into_vec()
            .unwrap()
            .try_into()
            .unwrap();
        let (expected, _) = crown_derive::solana_pda_address(program, &[b"escrow", &salt]).unwrap();
        assert_eq!(escrow, expected.to_vec());

        // Permuting the row is a different escrow: recipients and shares are
        // positional, so a reordered declaration must not reuse the address.
        let permuted = derive_escrow(
            &spec(),
            &donor,
            &[[0x22; 32], [0x24; 32], [0x23; 32]],
            &shares,
            1_000_000,
            12,
            1_900_000_000,
            2_592_000,
            &resolver,
            7,
        )
        .unwrap();
        assert_ne!(escrow, permuted);
    }

    /// Every recipient of the row is length-checked, not just the first: a
    /// non-key in any position must fail before a signature is paid for.
    #[test]
    fn a_short_recipient_in_any_position_is_rejected() {
        for bad in 0..3usize {
            let mut recipients = vec![vec![0x22; 32]; 3];
            recipients[bad] = vec![0x22; 31];
            assert_eq!(
                derive_escrow(
                    &spec(),
                    &[0x11; 32],
                    &recipients,
                    &[4_000, 3_000, 3_000],
                    34,
                    1,
                    0,
                    1,
                    &[0x33; 32],
                    0
                ),
                Err(AuthError::BadFieldLength)
            );
        }
    }

    /// Pins today's behaviour: a row whose shares do not match its recipients
    /// is **not** rejected — it derives some address and costs a threshold
    /// signature. Harmless (the shape refuses to be born that way, so no
    /// escrow lives there) but an accepted spam vector, game-spec §13.1.
    /// If this ever starts erroring, that section and this test must change
    /// together.
    #[test]
    fn mismatched_shares_derive_an_unreachable_address() {
        let derive = |shares: &[u16]| {
            derive_escrow(
                &spec(),
                &[0x11; 32],
                &[[0x22; 32], [0x23; 32]],
                shares,
                1,
                1,
                0,
                1,
                &[0x33; 32],
                0,
            )
        };
        let matched = derive(&[6_000, 4_000]).unwrap();
        // Fewer shares than recipients, and more: both succeed today.
        assert_ne!(derive(&[6_000]).unwrap(), matched);
        assert_ne!(derive(&[6_000, 4_000, 1]).unwrap(), matched);
        assert_ne!(derive(&[]).unwrap(), matched);
    }

    #[test]
    fn baked_config_is_valid() {
        validate_config().unwrap();
    }

    /// A second well-formed entry, distinct from `spec()` in all three of
    /// id, domain and factory — the base every pairwise case perturbs.
    fn other_spec() -> ChainSpec {
        ChainSpec {
            id: "solana-mainnet",
            // base58 of [0x55; 32].
            factory: "6k78AbasGMFFrhG95Pj6jQbqkVt7FQMhVgemxJovWKR6",
            domain: "crown:stream:solana-mainnet",
            fee_bps: 300,
            fee_wallet: "5bV6jUfhDHCQVA1WfKBUnXUsboJgoKgkzkKcxr3joew5",
        }
    }

    /// Deploying with a table that fails any of these must trap in `init`.
    /// If a case stops being rejected, a canister ships that either resolves
    /// nothing (unparseable keys, no chains) or resolves one escrow under two
    /// chain names (a duplicated id, domain or factory).
    #[test]
    fn malformed_configs_are_rejected() {
        assert_eq!(validate_chains(&[]), Err(AuthError::MalformedConfig));

        let cases = [
            // Factory is not base58.
            ChainSpec {
                factory: "not base58 at all!",
                ..spec()
            },
            // Factory is base58 but not 32 bytes.
            ChainSpec {
                factory: "deadbeef",
                ..spec()
            },
            // Fee wallet is not base58.
            ChainSpec {
                fee_wallet: "0OIl",
                ..spec()
            },
            // Fee wallet is base58 but not 32 bytes.
            ChainSpec {
                fee_wallet: "deadbeef",
                ..spec()
            },
            // A fee of the whole donation or more leaves the recipients nothing.
            ChainSpec {
                fee_bps: 10_000,
                ..spec()
            },
            ChainSpec {
                fee_bps: u16::MAX,
                ..spec()
            },
            // An empty domain is no domain separator at all.
            ChainSpec {
                domain: "",
                ..spec()
            },
        ];
        for case in cases {
            assert_eq!(
                validate_chains(&[case]),
                Err(AuthError::MalformedConfig),
                "accepted a malformed chain entry"
            );
        }
    }

    /// The salt is chain-independent, so two entries sharing a factory (or a
    /// domain) would derive and sign one address under two names; a shared id
    /// makes the second entry unreachable. Any of the three must fail deploy.
    #[test]
    fn chains_must_be_pairwise_distinct() {
        assert_eq!(validate_chains(&[spec(), other_spec()]), Ok(()));

        let clashes = [
            ChainSpec {
                id: spec().id,
                ..other_spec()
            },
            ChainSpec {
                domain: spec().domain,
                ..other_spec()
            },
            ChainSpec {
                factory: spec().factory,
                ..other_spec()
            },
        ];
        for clash in clashes {
            assert_eq!(
                validate_chains(&[spec(), clash]),
                Err(AuthError::MalformedConfig),
                "accepted two chains that collide"
            );
        }
    }

    // ---- cancel authorization ----------------------------------------------

    #[test]
    fn cancel_authorization_is_pinned() {
        assert_eq!(
            cancel_authorization("solana-devnet", CANISTER, &[0xCC; 32]),
            format!(
                "crown:subscription:v1\n\
                 action: cancel\n\
                 chain: solana-devnet\n\
                 canister: {CANISTER}\n\
                 escrow: {ESCROW_B58}\n"
            )
        );
        assert_eq!(ACTION_CANCEL, "cancel");
    }

    /// The whole point: Phantom rejects anything that is not valid UTF-8, so
    /// a donor could not cancel at all while this was binary.
    #[test]
    fn the_message_is_printable_ascii() {
        let message = cancel_authorization("solana-devnet", CANISTER, &[0xFF; 32]);
        assert!(
            message
                .chars()
                .all(|c| c == '\n' || c.is_ascii_graphic() || c == ' '),
            "not printable: {message:?}"
        );
    }

    /// One signature opens one escrow: distinct declarations, distinct texts.
    #[test]
    fn distinct_authorizations_render_distinctly() {
        let messages = [
            cancel_authorization("solana-devnet", CANISTER, &[0xCC; 32]),
            cancel_authorization("solana-devnet", CANISTER, &[0xCD; 32]),
            cancel_authorization("solana-mainnet", CANISTER, &[0xCC; 32]),
            cancel_authorization("solana-devnet", "aaaaa-aa", &[0xCC; 32]),
        ];
        let count = messages.len();
        let seen: std::collections::BTreeSet<String> = messages.into_iter().collect();
        assert_eq!(seen.len(), count);
    }

    #[test]
    fn signature_roundtrip_and_rejections() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let address = key.verifying_key().to_bytes().to_vec();
        let message = cancel_authorization("solana-devnet", CANISTER, &[2; 32]);
        let sig = key.sign(message.as_bytes()).to_bytes().to_vec();
        verify_wallet_signature(message.as_bytes(), &sig, &address).unwrap();

        // Foreign signer.
        let other = ed25519_dalek::SigningKey::from_bytes(&[10; 32])
            .verifying_key()
            .to_bytes()
            .to_vec();
        assert_eq!(
            verify_wallet_signature(message.as_bytes(), &sig, &other),
            Err(AuthError::BadSignature)
        );
        // Foreign escrow: same signer, different address.
        let foreign = cancel_authorization("solana-devnet", CANISTER, &[3; 32]);
        assert_eq!(
            verify_wallet_signature(foreign.as_bytes(), &sig, &address),
            Err(AuthError::BadSignature)
        );
        // Foreign canister: same escrow, different canister_id.
        let foreign = cancel_authorization("solana-devnet", "aaaaa-aa", &[2; 32]);
        assert_eq!(
            verify_wallet_signature(foreign.as_bytes(), &sig, &address),
            Err(AuthError::BadSignature)
        );
        // Foreign cluster: same everything, different chain id.
        let foreign = cancel_authorization("solana-mainnet", CANISTER, &[2; 32]);
        assert_eq!(
            verify_wallet_signature(foreign.as_bytes(), &sig, &address),
            Err(AuthError::BadSignature)
        );
    }

    /// Wrong-sized fields must be values, not panics: `try_into` on a slice
    /// is the only thing standing between an ingress argument of any length
    /// and a fixed-size array. A regression here traps the canister on a
    /// call anyone can make.
    #[test]
    fn wrong_sized_signature_fields_are_rejected() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
        let address = key.verifying_key().to_bytes().to_vec();
        let message = cancel_authorization("solana-devnet", CANISTER, &[2; 32]);
        let sig = key.sign(message.as_bytes()).to_bytes().to_vec();

        for len in [0usize, 31, 33, 64] {
            assert_eq!(
                verify_wallet_signature(message.as_bytes(), &sig, &vec![7u8; len]),
                Err(AuthError::BadFieldLength),
                "signer of {len} bytes was not refused as a length"
            );
        }
        for len in [0usize, 32, 63, 65, 128] {
            assert_eq!(
                verify_wallet_signature(message.as_bytes(), &vec![7u8; len], &address),
                Err(AuthError::BadSignature),
                "signature of {len} bytes was not refused"
            );
        }
        // A signer of the right length that is not a curve point.
        assert_eq!(
            verify_wallet_signature(message.as_bytes(), &sig, &[0xFF; 32]),
            Err(AuthError::BadSignature)
        );
    }
}
