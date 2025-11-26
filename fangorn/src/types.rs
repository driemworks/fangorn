use anyhow::Result;
use iroh::SecretKey as IrohSecretKey;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::OsRng;
use silent_threshold_encryption::aggregate::SystemPublicKeys;
use silent_threshold_encryption::{
    crs::CRS,
    setup::{LagPolys, PublicKey, SecretKey},
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

pub struct StartNodeParams<C: Pairing> {
    pub iroh_secret_key: IrohSecretKey,
    pub secret_key: SecretKey<C>,
    pub bind_port: u16,
}

/// params to start a new node
impl<C: Pairing> StartNodeParams<C> {
    pub fn rand(bind_port: u16, index: usize) -> Self {
        // build new
        // let path = format!("tmp/keystore/{}/")
        Self {
            // sr25519_secret_key:
            iroh_secret_key: IrohSecretKey::generate(&mut rand::rng()),
            secret_key: SecretKey::<C>::new(&mut OsRng, index),
            bind_port,
        }
    }
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
pub struct State<C: Pairing> {
    pub config: Option<Config<C>>,
    pub hints: Option<Vec<PublicKey<C>>>,
    // TODO: secure vault for key mgmt
    pub sk: SecretKey<C>,
    pub system_keys: Option<SystemPublicKeys<C>>,
}

impl<C: Pairing> State<C> {
    pub fn empty(sk: SecretKey<C>) -> Self {
        Self {
            config: None,
            hints: None,
            system_keys: None,
            sk,
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
