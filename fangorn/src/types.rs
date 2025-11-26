use anyhow::Result;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::OsRng;
use secrecy::SecretString;
use silent_threshold_encryption::aggregate::SystemPublicKeys;
use silent_threshold_encryption::{
    crs::CRS,
    setup::{LagPolys, PublicKey},
};

use codec::{Decode, Encode};

// prefixes for keys for different types of documents
pub const RPC_KEY_PREFIX: &str = "rpc-addr-";
pub const CONFIG_KEY: &str = "config-key-";
pub const SYSTEM_KEYS_KEY: &str = "sys-keys-";

pub const MAX_COMMITTEE_SIZE: usize = 2;

/// the curve (bls12-381)
pub type E = ark_bls12_381::Bls12_381;
/// the g2 group
pub type G2 = <E as Pairing>::G2;

pub type OpaqueCid = Vec<u8>;

#[derive(Clone, Debug, Encode, Decode, PartialEq)]
pub enum Tag {
    Config,
    Hint,
    Doc,
    SystemKeys,
    DecryptionRequest,
}

#[derive(Clone, Debug, Encode, Decode)]
pub struct Announcement {
    pub tag: Tag,
    pub data: Vec<u8>,
}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub struct Config<C: Pairing> {
    pub crs: CRS<C>,
    pub lag_polys: LagPolys<<C as Pairing>::ScalarField>,
    pub size: usize,
}

impl<C: Pairing> Config<C> {
    pub fn rand(size: usize) -> Self {
        let crs = CRS::<C>::new(size, &mut OsRng).unwrap();
        let lag_polys = LagPolys::<<C as Pairing>::ScalarField>::new(size).unwrap();
        Self {
            crs,
            lag_polys,
            size,
        }
    }
}

#[derive(Clone)]
pub struct VaultConfig {
    pub vault_dir: String,
    pub substrate_name: String,
    pub vault_pswd: Option<SecretString>,
    pub iroh_key_pswd: Option<SecretString>,
    pub ste_key_pswd: Option<SecretString>,
    pub substrate_pswd: Option<SecretString>,
}

impl Default for VaultConfig {
    fn default() -> Self {
        Self {
            vault_dir: String::from("tmp/keystore"),
            substrate_name: String::from("sr25519"),
            vault_pswd: None,
            iroh_key_pswd: None,
            ste_key_pswd: None,
            substrate_pswd: None,
        }
    }
}

#[derive(Clone)]
pub struct State<C: Pairing> {
    pub config: Option<Config<C>>,
    pub hints: Option<Vec<PublicKey<C>>>,
    pub system_keys: Option<SystemPublicKeys<C>>,
}

impl<C: Pairing> State<C> {
    pub fn empty() -> Self {
        Self {
            config: None,
            hints: None,
            system_keys: None,
        }
    }

    pub fn update(&mut self, announcement: Announcement) {
        match announcement.tag {
            Tag::Config => {
                println!("Received Config");
                let config: Config<C> =
                    Config::deserialize_compressed(&announcement.data[..]).unwrap();
                self.config = Some(config.clone());
            }
            Tag::Hint => {
                let hint: PublicKey<C> =
                    PublicKey::deserialize_compressed(&announcement.data[..]).unwrap();
                if let Some(h) = &self.hints {
                    let mut hints = h.clone();
                    hints.push(hint);
                    self.hints = Some(hints.clone());
                } else {
                    self.hints = Some(vec![hint]);
                }
            }
            _ => {
                // do nothing for other tags for now
                // eventually we could use this to charge for storage?
            }
        }
    }
}
