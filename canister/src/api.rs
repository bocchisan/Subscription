//! The Candid surface. Updates are exactly the frozen allowlist. Ingress is
//! open to anyone: the right is the derivation arithmetic, the schedule, and
//! — for a cancel — the donor's wallet signature; never who sends the call.

use candid::CandidType;
use serde::Deserialize;
use serde_bytes::ByteBuf;
use subscription_logic as logic;

use crate::auth;

fn schedule_error_text(error: logic::schedule::ScheduleError) -> String {
    match error {
        logic::schedule::ScheduleError::NotDue => "chunk not due yet",
        logic::schedule::ScheduleError::Overflow => "schedule out of range",
    }
    .to_string()
}

fn subscription_id_of(bytes: &[u8]) -> Result<[u8; 32], String> {
    bytes
        .try_into()
        .map_err(|_| "subscription id must be 32 bytes".to_string())
}

/// The canister's own principal, in the text form the signed message shows.
fn canister_id() -> String {
    ic_cdk::api::canister_self().to_text()
}

// ---- updates -----------------------------------------------------------------

/// The RESOLVER birth field for escrows of one subscription: the derived
/// Ed25519 pubkey at path [subscription_id]. An update, not a query: the key
/// derivation is an asynchronous management canister call and the canister
/// keeps no stored copy to serve — it has no storage at all.
#[ic_cdk::update]
async fn get_resolver(chain: String, subscription_id: ByteBuf) -> Result<ByteBuf, String> {
    auth::spec_of(&chain).map_err(|e| e.text().to_string())?;
    let id = subscription_id_of(&subscription_id)?;
    let resolver = crate::sign::resolver_key(&id).await?;
    Ok(ByteBuf::from(resolver))
}

#[derive(CandidType, Deserialize)]
pub struct ReleaseArg {
    pub chain: String,
    pub subscription_id: ByteBuf,
    // Birth fields of the escrow, sans resolver (docs/game-spec.md §7): the
    // resolver is derived, never declared.
    pub donor: ByteBuf,
    pub recipients: Vec<ByteBuf>,
    pub shares: Vec<u16>,
    pub chunk: u64,
    pub n_chunks: u16,
    pub t0: i64,
    pub period: i64,
    pub nonce: u64,
    /// The chunk to release. Order among chunks is the onchain form's law,
    /// not this canister's: a signature for the wrong turn does not execute.
    pub index: u16,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SignedRelease {
    pub escrow: ByteBuf,
    pub index: u16,
    pub signature: ByteBuf,
}

/// The signature on demand for one due chunk (docs/game-spec.md §7). The law
/// is checked before anything is paid for; it is monotone in time, so the
/// awaits after it cannot un-due the chunk. Nothing is stored — a retry
/// re-signs the same message.
#[ic_cdk::update]
async fn request_release(arg: ReleaseArg) -> Result<SignedRelease, String> {
    let spec = auth::spec_of(&arg.chain).map_err(|e| e.text().to_string())?;
    let id = subscription_id_of(&arg.subscription_id)?;

    logic::schedule::release_due(crate::now_seconds(), arg.t0, arg.period, arg.index)
        .map_err(schedule_error_text)?;

    let resolver = crate::sign::resolver_key(&id).await?;
    let escrow = auth::derive_escrow(
        spec,
        &arg.donor,
        &arg.recipients,
        &arg.shares,
        arg.chunk,
        arg.n_chunks,
        arg.t0,
        arg.period,
        &resolver,
        arg.nonce,
    )
    .map_err(|e| e.text().to_string())?;

    let program = bs58::decode(spec.factory)
        .into_vec()
        .map_err(|_| "malformed factory program id")?;
    let message = crate::sign::release_message(spec.domain, &program, &escrow, arg.index);
    let signature = crate::sign::sign_for_subscription(&id, &resolver, &message).await?;
    Ok(SignedRelease {
        escrow: ByteBuf::from(escrow),
        index: arg.index,
        signature: ByteBuf::from(signature),
    })
}

#[derive(CandidType, Deserialize)]
pub struct CancelArg {
    pub chain: String,
    pub subscription_id: ByteBuf,
    // Birth fields, as in ReleaseArg. The donor doubles as the verifying key
    // of the authorization: forging it changes the address, so an executable
    // cancel for a foreign escrow does not exist (docs/game-spec.md §7).
    pub donor: ByteBuf,
    pub recipients: Vec<ByteBuf>,
    pub shares: Vec<u16>,
    pub chunk: u64,
    pub n_chunks: u16,
    pub t0: i64,
    pub period: i64,
    pub nonce: u64,
    /// The donor's Ed25519 signature over the cancel authorization (§8).
    pub signature: ByteBuf,
}

#[derive(CandidType, Deserialize, Debug)]
pub struct SignedCancel {
    pub escrow: ByteBuf,
    pub signature: ByteBuf,
}

/// The cancel signature on demand (docs/game-spec.md §7, §8): the whole
/// unreleased remainder back to the donor, by the donor's word alone. The
/// escrow address must be derived before the authorization can be checked,
/// so an unauthorized request still costs one key derivation — accepted
/// (game-spec §13.1). Terminality is onchain; a replay is harmless.
#[ic_cdk::update]
async fn request_cancel(arg: CancelArg) -> Result<SignedCancel, String> {
    let spec = auth::spec_of(&arg.chain).map_err(|e| e.text().to_string())?;
    let id = subscription_id_of(&arg.subscription_id)?;

    let resolver = crate::sign::resolver_key(&id).await?;
    let escrow = auth::derive_escrow(
        spec,
        &arg.donor,
        &arg.recipients,
        &arg.shares,
        arg.chunk,
        arg.n_chunks,
        arg.t0,
        arg.period,
        &resolver,
        arg.nonce,
    )
    .map_err(|e| e.text().to_string())?;

    let authorization = auth::cancel_authorization(&arg.chain, &canister_id(), &escrow);
    auth::verify_wallet_signature(authorization.as_bytes(), &arg.signature, &arg.donor)
        .map_err(|e| e.text().to_string())?;

    let program = bs58::decode(spec.factory)
        .into_vec()
        .map_err(|_| "malformed factory program id")?;
    let message = crate::sign::cancel_message(spec.domain, &program, &escrow);
    let signature = crate::sign::sign_for_subscription(&id, &resolver, &message).await?;
    Ok(SignedCancel {
        escrow: ByteBuf::from(escrow),
        signature: ByteBuf::from(signature),
    })
}

// ---- queries -----------------------------------------------------------------

#[ic_cdk::query]
fn get_logic_version() -> u32 {
    logic::LOGIC_VERSION
}
