//! E2e helper: builds the donor's cancel authorization and signs raw bytes
//! with wallet keys, so the shell scripts never re-implement the byte
//! protocol.
//!
//! Usage:
//!   participant cancel-authorization <chain> <canister-principal> <escrow_hex32>
//!   participant sol-sign <keypair.json> <message-file>
//!   participant sol-address <keypair.json>

use candid::Principal;
use subscription::auth;

fn hex_arg(text: &str) -> Vec<u8> {
    hex::decode(text.strip_prefix("0x").unwrap_or(text)).expect("hex argument")
}

/// Standard solana keypair file: a JSON array of 64 bytes, secret ‖ public.
fn solana_key(path: &str) -> ed25519_dalek::SigningKey {
    let text = std::fs::read_to_string(path).expect("keypair file");
    let bytes: Vec<u8> = text
        .trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(|part| part.trim().parse().expect("keypair byte"))
        .collect();
    let secret: [u8; 32] = bytes[..32].try_into().expect("keypair length");
    ed25519_dalek::SigningKey::from_bytes(&secret)
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let out = match args.get(1).map(String::as_str) {
        Some("cancel-authorization") => {
            let [chain, canister, escrow] = &args[2..] else {
                panic!("cancel-authorization <chain> <canister-principal> <escrow_hex32>");
            };
            let canister = Principal::from_text(canister).expect("principal");
            auth::cancel_authorization(chain, &canister.to_text(), &hex_arg(escrow))
        }
        // The message is text with newlines in it, so it travels by file.
        Some("sol-sign") => {
            let [keypair, message_file] = &args[2..] else {
                panic!("sol-sign <keypair.json> <message-file>");
            };
            use ed25519_dalek::Signer;
            let key = solana_key(keypair);
            let message = std::fs::read(message_file).expect("message file");
            hex::encode(key.sign(&message).to_bytes())
        }
        Some("sol-address") => {
            let [keypair] = &args[2..] else {
                panic!("sol-address <keypair.json>");
            };
            hex::encode(solana_key(keypair).verifying_key().to_bytes())
        }
        _ => panic!("unknown subcommand"),
    };
    // No trailing newline: the caller redirects this into the file that gets
    // signed, and one stray byte is a different message.
    print!("{out}");
}
