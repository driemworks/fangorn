use crate::backend::BlockchainBackend;
use crate::gadget::*;
use async_trait::async_trait;
use std::sync::Arc;
use subxt::ext::codec::{Decode, Encode};

#[derive(Debug)]
pub struct Psp22Gadget {
    contract_address: String,
    backend: Arc<dyn BlockchainBackend>,
}

impl Psp22Gadget {
    pub fn new(contract_address: String, backend: Arc<dyn BlockchainBackend>) -> Self {
        Self {
            contract_address,
            backend,
        }
    }
}

#[async_trait]
impl Gadget for Psp22Gadget {
    fn intent_type_id(&self) -> &'static str {
        "Psp22"
    }

    // The statement is "This public key owns an NFT with id X in the contract" (note: no actual sig verification YET)
    fn create_statement(&self, question: &[u8], _answer: &[u8]) -> Result<Vec<u8>, IntentError> {
        // question = token_id
        Ok(question.to_vec())
    }

    // witness = account pubkey (32 bytes)
    // statement = token_id
    async fn verify_witness(&self, witness: &[u8], statement: &[u8]) -> Result<bool, IntentError> {
        println!("verifying the witness");

        let pubkey_string: String =
            String::from_utf8(witness.to_vec()).expect("Invalid UTF-8 sequence");
        println!("WE DECODED THE pubkey: {:?}", pubkey_string.clone());
        let witness = crate::utils::decode_public_key(&pubkey_string);

        if witness.len() != 32 {
            return Err(IntentError::VerificationError(
                "Witness must be 32-byte account ID".into(),
            ));
        }

        if statement.len() != 48 {
            return Err(IntentError::VerificationError(
                "Statement must be 48 bytes (32 addr + 16 balance)".into(),
            ));
        }

        // Decode statement to extract contract address and minimum balance
        // convert to string
        let token_contract: [u8; 32] = statement[..32].try_into().unwrap();
        // then decode ss58 (this seeem roundabout...)

        let minimum_balance = u128::from_le_bytes(
            statement[32..48]
                .try_into()
                .map_err(|_| IntentError::VerificationError("Invalid balance bytes".into()))?,
        );

        // Query PSP22::balance_of(witness)
        let mut call_data = Vec::new();
        call_data.extend(witness); // account_id

        let selector = self.backend.selector("PSP22::balance_of");

        println!("querying token contract");
        let result = self
            .backend
            .query_contract(token_contract, selector, call_data)
            .await
            .map_err(|e| IntentError::VerificationError(format!("Query failed: {}", e)))?;

        // Decode balance from contract response
        let mut data = result;
        if !data.is_empty() {
            data.remove(0); // Remove status byte
        }

        let balance = u128::decode(&mut &data[..])
            .map_err(|e| IntentError::VerificationError(format!("Decode failed: {}", e)))?;

        // Verify: does the witness have enough tokens?
        Ok(balance >= minimum_balance)
    }

    /// expected format: data = "contract_addr, min_balance"
    fn parse_intent_data(&self, data: &str) -> Result<ParsedIntentData, IntentError> {
        // the intent is the contract_addr and min_balance encoded in a vec
        let parts: Vec<&str> = data.split(',').collect();
        if parts.len() != 2 {
            return Err(IntentError::ParseError(
                "PSP22 format: contract_address,minimum_balance".into(),
            ));
        }

        // 32 bytes
        let contract_addr = crate::utils::decode_contract_addr(parts[0].trim());
        // hex::decode(parts[0].trim())
        //     .map_err(|_| IntentError::ParseError("Invalid hex address".into()))?;

        if contract_addr.len() != 32 {
            return Err(IntentError::ParseError("Address must be 32 bytes".into()));
        }

        // 16 bytes
        let min_balance: u128 = parts[1]
            .trim()
            .parse()
            .map_err(|_| IntentError::ParseError("Invalid minimum_balance".into()))?;

        // build question: contract_address (32) || minimum_balance (16)
        let mut question = contract_addr.to_vec();
        question.extend(&min_balance.to_le_bytes());

        let answer = Vec::new(); // No predetermined answer for NFT ownership

        Ok(ParsedIntentData { question, answer })
    }
}

#[cfg(test)]
mod test {

    use super::*;

    fn test_can_parse_intent_data() {}
}
