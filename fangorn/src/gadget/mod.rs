//! Extensible intent framework for fangorn

use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::{collections::HashMap, fmt::Debug, sync::Arc};

pub mod password;
pub mod psp22;

pub use psp22::Psp22Gadget;
pub use password::PasswordGadget;

#[async_trait]
pub trait Gadget: Send + Sync + Debug {
    /// The gadget's intent type identifier
    fn intent_type_id(&self) -> &'static str;

    /// Verify a witness against a statement
    async fn verify_witness(&self, witness: &[u8], statement: &[u8]) -> Result<bool, IntentError>;

    /// Parse intent-specific data from string (todo: define parsing logic)
    fn parse_intent_data(&self, data: &str) -> Result<Vec<u8>, IntentError>;
}

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
    pub async fn parse_intent(&self, input: &str) -> Result<Intent, IntentError> {
        let (intent_type_str, data) =
            parse_intent_string(input).map_err(|e| IntentError::ParseError(format!("{:?}", e)))?;

        let gadget = self
            .get_gadget(intent_type_str)
            .ok_or_else(|| IntentError::UnknownIntentType(intent_type_str.to_string()))?;

        let statement = gadget.parse_intent_data(data)?;

        Ok(Intent {
            intent_type: intent_type_str.to_string(),
            statement,
            gadget: Some(gadget),
        })
    }

    /// Verify a witness against an intent
    pub async fn verify_intent(
        &self,
        intent: &Intent,
        witness: &[u8],
    ) -> Result<bool, IntentError> {
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
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Intent {
    pub intent_type: String,
    pub statement: Vec<u8>,
    #[serde(skip)]
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

/// parse IntentType(witness)
// TODO: modify parsing logic to parse multiple intent strings
// Type1(witness1), Type2(witnes2)
fn parse_intent_string(input: &str) -> Result<(&str, &str), nom::Err<nom::error::Error<&str>>> {
    let (input, intent_type) = nom::bytes::complete::take_until("(")(input)?;
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
    Ok((intent_type, password))
}

#[cfg(test)]
pub mod test {

    use super::*;

    #[test]
    fn parse_intent_works_with_plain_string_data() {
        let intent = "Password(this is my cool password_1235*(*()C11JKH))";
        let (intent_type, password) = parse_intent_string(&intent).unwrap();
        assert_eq!(intent_type, "Password");
        assert_eq!(password, "this is my cool password_1235*(*()C11JKH)");
    }
}
