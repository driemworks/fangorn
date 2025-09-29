use anyhow::Result;
use iroh::SecretKey as IrohSecretKey;

use ark_ec::pairing::Pairing;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::rngs::OsRng;
use silent_threshold_encryption::{
    crs::CRS,
    setup::{LagPolys, PublicKey, SecretKey},
};

use codec::{Decode, Encode};

pub(crate) const CONFIG_KEY: &str = "config-key";

pub(crate) type E = ark_bls12_381::Bls12_381;
pub(crate) type G2 = <E as Pairing>::G2;
// pub(crate) type Fr = <E as Pairing>::ScalarField;
// pub(crate) type UniPoly381<C> = DensePolynomial<<C as Pairing>::ScalarField>;

#[derive(Clone, Debug, Encode, Decode)]
pub(crate) enum Tag {
    Config,
    Hint,
}

#[derive(Clone, Debug, Encode, Decode)]
pub(crate) struct Announcement {
    pub(crate) tag: Tag,
    pub(crate) data: Vec<u8>,
}

pub struct StartNodeParams<C: Pairing> {
    pub(crate) iroh_secret_key: IrohSecretKey,
    pub(crate) secret_key: SecretKey<C>,
    pub(crate) bind_port: u16,
}

/// params to start a new node
impl<C: Pairing> StartNodeParams<C> {
    pub fn rand(bind_port: u16, index: usize) -> Self {
        Self {
            iroh_secret_key: IrohSecretKey::generate(OsRng),
            secret_key: SecretKey::<C>::new(&mut OsRng, index),
            bind_port,
        }
    }
}

#[derive(Clone, CanonicalDeserialize, CanonicalSerialize)]
pub(crate) struct Config<C: Pairing> {
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
}

impl<C: Pairing> State<C> {
    pub fn empty(sk: SecretKey<C>) -> Self {
        Self {
            config: None,
            hints: None,
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
                println!("Received Hint");
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
        }
    }
}
