use crate::{backend::substrate::SubstrateBackend, gadget::*};
use async_trait::async_trait;
use sp_core::{Pair, sr25519};
use std::fmt::Debug;

/// Verifies sr25519 signatures
#[derive(Debug)]
pub struct Sr25519Gadget {
    /// The blockchain backend
    backend: Arc<SubstrateBackend>,
}

impl Sr25519Gadget {
    pub fn new(backend: Arc<SubstrateBackend>) -> Self {
        Self { backend }
    }
}

#[async_trait]
impl Gadget for Sr25519Gadget {
    fn intent_type_id(&self) -> &'static str {
        "Sr25519"
    }

    /// witness = (public_key, signature)
    /// statement = the message that was signed (leave empty if you just signed a message containing the acct nonce)
    async fn verify_witness(&self, witness: &[u8], statement: &[u8]) -> Result<bool, IntentError> {
        // parse the witness
        if witness.len() != 176 {
            return Err(IntentError::VerificationError(format!(
                "Witness must be 176 bytes (Pubkey-as-ss58 + Signature). Got {}",
                witness.len()
            )));
        }

        // this is kind of weird.. need a better way to parse the witness..
        let pubkey_bytes: &[u8; 48] = witness[..48]
            .try_into()
            .map_err(|_| IntentError::VerificationError("Invalid Pubkey length".into()))?;

        let pubkey_string: String =
            String::from_utf8(pubkey_bytes.to_vec()).expect("Invalid UTF-8 sequence");

        let pubkey_bytes = crate::utils::decode_public_key(&pubkey_string);

        let sig_hex = &witness[48..];
        let signature_bytes: [u8; 64] = hex::decode(&sig_hex)
            .unwrap()
            .try_into()
            .map_err(|_| IntentError::VerificationError("Invalid Signature length".into()))?;

        let public_key = sr25519::Public::from_raw(pubkey_bytes);
        let signature = sr25519::Signature::try_from(signature_bytes).map_err(|_| {
            IntentError::VerificationError("Invalid Sr25519 Signature format".into())
        })?;
        // fetch the nonce
        let nonce = self.backend.nonce(pubkey_bytes).await.unwrap();
        println!("Using nonce: {:?}", nonce);
        // build the message: statement || nonce (statement is empty)
        let mut message = statement.to_vec();
        message.extend(nonce.to_le_bytes());
        // verify the signature
        Ok(sr25519::Pair::verify(&signature, message, &public_key))
    }

    // This type has no data to parse (yet) - we could make this a generic sig verifier and
    // introduce data=curve/cipher (e.g. Signed(Sr25519))
    fn parse_intent_data(&self, _data: &str) -> Result<Vec<u8>, IntentError> {
        Ok(Vec::new())
    }
}
