use super::*;
use ark_ec::pairing::Pairing;
use async_trait::async_trait;
use cid::Cid;
use codec::{Decode, Encode};
use multihash_codetable::{Code, MultihashDigest};
use std::fs::OpenOptions;
use std::io::prelude::*;
use std::path::PathBuf;
use std::str::FromStr;
use tokio::fs;

use crate::node::Node;
use crate::types::*;
use iroh::{NodeAddr, PublicKey as IrohPublicKey};
use iroh_docs::{
    engine::LiveEvent,
    rpc::{
        client::docs::{Doc, ShareMode},
        proto::{Request, Response},
    },
    store::{FlatQuery, QueryBuilder},
    DocTicket,
};
use quic_rpc::transport::flume::FlumeConnector;

// / The codec for generating CIDs
const RAW: u64 = 0x55;

pub struct IrohDocStore<C: Pairing> {
    pub node: Node<C>,
    pub doc_stream: Doc<FlumeConnector<Response, Request>>,
}

impl<C: Pairing> IrohDocStore<C> {
    pub async fn new(node: Node<C>, ticket: String) -> Self {
        let doc_ticket = DocTicket::from_str(&ticket).unwrap();
        let doc_stream = node.docs().import(doc_ticket).await.unwrap();
        Self { node, doc_stream }
    }

    /// build a unique key for the data (it's a cid)
    fn build_cid(&self, data: &Data) -> Cid {
        let hash = Code::Sha2_256.digest(data);
        let cid = Cid::new_v1(RAW, hash);
        cid
    }
}

#[async_trait]
impl<C: Pairing> SharedStore<Cid, Data> for IrohDocStore<C> {
    async fn add(&self, data: &Data) -> Result<Cid> {
        let cid = self.build_cid(data);
        let announcement = Announcement {
            tag: Tag::Doc,
            data: data.to_vec(),
        };

        self.doc_stream
            .set_bytes(
                self.node.docs().authors().default().await?,
                cid.to_string(),
                announcement.encode(),
            )
            .await?;

        Ok(cid)
    }

    async fn fetch(&self, cid: &Cid) -> Result<Option<Data>> {
        let entry = self
            .doc_stream
            .get_one(
                QueryBuilder::<FlatQuery>::default()
                    .key_exact(cid.to_string())
                    .build(),
            )
            .await?;

        match entry {
            Some(e) => {
                let hash = e.content_hash();
                let content = self.node.blobs().read_to_bytes(hash).await?;
                let announcement = Announcement::decode(&mut &content[..])?;
                Ok(Some(announcement.data))
            }
            None => Ok(None),
        }
    }

    async fn remove(&self, cid: &Cid) -> Result<()> {
        self.doc_stream
            .del(self.node.docs().authors().default().await?, cid.to_string())
            .await?;
        Ok(())
    }
}

impl<C: Pairing> DocStore for IrohDocStore<C> {}
