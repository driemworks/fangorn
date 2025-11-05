//! intents for fangorn.
// intents allow users to associate data access
// with an np-hard problem
use super::challenges::Challenge;
use crate::entish::challenges::PasswordChallenge;
use multihash_codetable::{Code, MultihashDigest};
use nom::{
    IResult, Parser,
    bytes::complete::{tag, take_until},
    sequence::delimited,
};
use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

/// types of policies
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum IntentType {
    /// The intent is satisfied if you provide a valid password
    Password,
    /// The intent type could not be identified.
    Unknown,
}

impl FromStr for IntentType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "Password" => Ok(IntentType::Password),
            _ => Err(format!("Unknown intent type: {}", s)),
        }
    }
}

impl fmt::Display for IntentType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            IntentType::Password => write!(f, "Password"),
            IntentType::Unknown => write!(f, "Unknown"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Intent {
    pub intent_type: IntentType,
    pub parameters: Vec<u8>,
}

impl Intent {
    /// convert a policy to an NP-statement
    // pub fn to_statement(&self) -> Statement {
    //     Statement(self.parameters.clone())
    // }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).unwrap()
    }

    /// Create an NP-hard problem
    pub fn create_intent<C: Challenge>(
        question: &Vec<u8>,
        answer: &Vec<u8>,
        intent_type: IntentType,
    ) -> Self {
        let stmt = C::create_challenge_statement(question, answer);
        let stmt_unwrap = stmt.expect("There was an issue unwrapping the statement");
        Self {
            intent_type: intent_type,
            parameters: stmt_unwrap.0,
        }
    }

    /// Parse a string into an Intent
    pub fn try_from_string(input: &str) -> Result<Self, String> {
        let (intent_type_str, password) = parse_intent_string(input).unwrap();
        //.map_err(|e| format!("Failed to parse intent: {}", e))?;

        let intent_type = IntentType::from_str(intent_type_str)?;

        match intent_type {
            IntentType::Password => {
                let answer = password.as_bytes().to_vec();
                // Hash the password as the question
                let question = Code::Sha2_256.digest(&answer).to_bytes();

                // TODO: can we somehow infer the challenge type based on intent type?
                Ok(Self::create_intent::<PasswordChallenge>(
                    &question,
                    &answer,
                    IntentType::Password,
                ))
            }
            _ => Err(format!("Unknown intent type: {}", intent_type)),
        }
    }
}

impl From<Vec<u8>> for Intent {
    fn from(bytes: Vec<u8>) -> Self {
        serde_json::from_slice(&bytes).unwrap()
    }
}

// intent parser function
fn parse_intent_string(input: &str) -> Result<(&str, &str), nom::Err<nom::error::Error<&str>>> {
    let (input, intent_type) = take_until("(")(input)?;
    let (input, _) = tag("(")(input)?;

    // Find the matching closing paren by counting
    let mut depth = 1;
    let mut end_pos = 0;

    // so passwords can contain parens
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
    let remaining = &input[end_pos + 1..];

    // // error if there's leftover input
    // if !remaining.is_empty() {
    //     return Err(nom::Err::Error(nom::error::Error::new(remaining, nom::error::ErrorKind::Eof)));
    // }

    Ok((intent_type, password))
}

#[cfg(test)]
pub mod test {
    use super::*;
    #[test]
    fn parse_intent_works() {
        let intent = "Password(this is my cool password_1235*(*()C11JKH))";
        let (intent_type, password) = parse_intent_string(&intent).unwrap();
        assert_eq!(intent_type, "Password");
        assert_eq!(password, "this is my cool password_1235*(*()C11JKH)");
    }
}
