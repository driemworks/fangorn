//! Extensible intent framework for fangorn

use async_trait::async_trait;
use codec::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug, sync::Arc};

pub mod password;
pub mod psp22;
pub mod sr25519;

pub use password::PasswordGadget;
pub use psp22::Psp22Gadget;
pub use sr25519::Sr25519Gadget;

#[async_trait]
pub trait Gadget: Send + Sync {
    /// The gadget's intent type identifier
    fn intent_type_id(&self) -> &'static str;

    /// Verify a witness against a statement
    async fn verify_witness(&self, witness: &[u8], statement: &[u8]) -> Result<bool, IntentError>;

    /// Parse intent-specific data from string (todo: define parsing logic)
    fn parse_intent_data(&self, data: &str) -> Result<Vec<u8>, IntentError>;
}

// TODO: use thiserror instead
#[derive(Debug)]
pub enum IntentError {
    ParseError(String),
    VerificationError(String),
    UnknownIntentType(String),
    SerializationError(String),
}

impl std::fmt::Display for IntentError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            IntentError::ParseError(s) => write!(f, "Parse error: {}", s),
            IntentError::VerificationError(s) => write!(f, "Verification error: {}", s),
            IntentError::UnknownIntentType(s) => write!(f, "Unknown intent type: {}", s),
            IntentError::SerializationError(s) => write!(f, "Serialization error: {}", s),
        }
    }
}

impl std::error::Error for IntentError {}

/// Registry for gadgets to allow for extensible gadgets to be used
#[derive(Clone)]
pub struct GadgetRegistry {
    gadgets: HashMap<String, Arc<dyn Gadget>>,
}

impl GadgetRegistry {
    pub fn new() -> Self {
        Self {
            gadgets: HashMap::new(),
        }
    }

    /// Register a new gadget
    pub fn register<M: Gadget + 'static>(&mut self, gadget: M) {
        let id = gadget.intent_type_id().to_string();
        self.gadgets.insert(id, Arc::new(gadget));
    }

    /// Get a gadget by type ID
    pub fn get_gadget(&self, intent_type: &str) -> Option<Arc<dyn Gadget>> {
        self.gadgets.get(intent_type).cloned()
    }

    /// Parse an intent string and create an Intent
    pub async fn parse_intents(&self, input: &str) -> Result<Vec<Intent>, IntentError> {
        let parsed_intents =
            parse_intent_string(input).map_err(|e| IntentError::ParseError(format!("{:?}", e)))?;

        let mut intents = Vec::new();

        for (intent_type_str, data) in parsed_intents {
            let gadget = self
                .get_gadget(intent_type_str)
                .ok_or_else(|| IntentError::UnknownIntentType(intent_type_str.to_string()))?;

            let statement = gadget.parse_intent_data(data)?;
            let intent = Intent {
                intent_type: intent_type_str.to_string(),
                statement,
                gadget: Some(gadget),
            };

            intents.push(intent)
        }

        Ok(intents)
    }

    pub async fn verify_intents(
        &self,
        intents: Vec<Intent>,
        mut witness: &[u8],
    ) -> Result<bool, IntentError> {
        // TODO: this coudl return Result<(), IntentError> instead
        // first we need to recover the witnesses
        let decoded_witnesses = Vec::<Vec<u8>>::decode(&mut witness).unwrap();
        assert!(
            decoded_witnesses.len() == intents.len(),
            "Mismatched intents and witnesses"
        );
        // TODO: this is a little dangerous: witnesses MUST be ordered
        // in the same order that gadgets were described when encrypting the message
        // if any single one fails, they all fail
        for (intent, witness) in intents.iter().zip(decoded_witnesses.iter()) {
            if !self.verify_intent(&intent, &witness).await? {
                // return an error if an intent is not valid
                return Err(IntentError::VerificationError(intent.intent_type.clone()));
            }
        }

        Ok(true)
    }

    /// Verify a witness against an intent
    async fn verify_intent(&self, intent: &Intent, witness: &[u8]) -> Result<bool, IntentError> {
        let gadget = match &intent.gadget {
            Some(m) => m.clone(),
            None => self
                .get_gadget(&intent.intent_type)
                .ok_or_else(|| IntentError::UnknownIntentType(intent.intent_type.clone()))?,
        };

        gadget.verify_witness(witness, &intent.statement).await
    }
}

/// An intent represents raw user input that can be parsed by the given gadget
#[derive(Clone, Serialize, Deserialize, Encode, Decode)]
pub struct Intent {
    pub intent_type: String,
    pub statement: Vec<u8>,
    #[serde(skip)]
    #[codec(skip)]
    pub gadget: Option<Arc<dyn Gadget>>,
}

impl Intent {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self).unwrap()
    }
}

impl From<Vec<u8>> for Intent {
    fn from(bytes: Vec<u8>) -> Self {
        serde_json::from_slice(&bytes).unwrap()
    }
}

/// intents are delimited with an && symbol (logical AND)
static DELIMITER: &str = "&&";

/// parse intent types and data from raw string input
/// it expects an '&&' delimited string, e.g. "Type1(witness1) && Type2(witness2)"
fn parse_intent_string(
    raw_input: &str,
) -> Result<Vec<(&str, &str)>, nom::Err<nom::error::Error<&str>>> {
    // split by &
    let parts: Vec<&str> = raw_input.split(DELIMITER).collect();
    // Q: should we have a max number of allowed intents?
    let mut output = Vec::new();

    for input in parts {
        let (input, intent_type) = nom::bytes::complete::take_until("(")(input.trim())?;
        let (input, _) = nom::bytes::complete::tag("(")(input)?;

        let mut depth = 1;
        let mut end_pos = 0;

        for (i, c) in input.char_indices() {
            if c == '(' {
                depth += 1;
            } else if c == ')' {
                depth -= 1;
                if depth == 0 {
                    end_pos = i;
                    break;
                }
            }
        }

        let password = &input[..end_pos];
        output.push((intent_type, password))
    }
    Ok(output)
}

#[cfg(test)]
pub mod test {

    use super::*;

    #[test]
    fn parse_single_intent_works() {
        let intent = "Password(this is my cool password_1235*(*()C11JKH))";
        let (intent_type, password) = parse_intent_string(&intent).unwrap()[0];
        assert_eq!(intent_type, "Password");
        assert_eq!(password, "this is my cool password_1235*(*()C11JKH)");
    }

    #[test]
    fn parse_multiple_intent_works() {
        let intent = "Intent1(data1) && Intent2(data2--$$#()) && Intent3()";
        let expected_output = vec![
            ("Intent1", "data1"),
            ("Intent2", "data2--$$#()"),
            ("Intent3", ""),
        ];
        let actual_output = parse_intent_string(&intent).unwrap();
        assert!(expected_output == actual_output);
    }
}
