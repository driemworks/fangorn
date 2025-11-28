use super::*;
use anyhow::Result;
use ark_ec::pairing::Pairing;
use async_trait::async_trait;
use cid::Cid;
use codec::{Decode, Encode};
use multihash_codetable::{Code, MultihashDigest};
use std::str::FromStr;
use std::sync::Arc;

use crate::backend::iroh::SharedIrohBackend;
use crate::Node;
use crate::types::*;
use iroh_docs::{DocTicket, api::Doc};

// The codec for generating CIDs
const RAW: u64 = 0x55;

#[derive(Clone)]
pub struct IrohDocStore<C: Pairing> {
    pub node: Node<C>,
    doc: Doc,
    backend: Arc<dyn SharedIrohBackend>,
}

impl<C: Pairing> IrohDocStore<C> {
    pub async fn new(node: Node<C>, ticket: &str, backend: Arc<dyn SharedIrohBackend>) -> Self {
        let doc_ticket = DocTicket::from_str(&ticket).unwrap();
        let doc = node.docs().import(doc_ticket).await.unwrap();
        Self { node, doc, backend }
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

        self.backend
            .write(&self.doc, &cid.to_string(), &announcement.encode())
            .await?;

        Ok(cid)
    }

    async fn fetch(&self, cid: &Cid) -> Result<Option<Data>> {
        if let Some(content) = self.backend.read(&self.doc, &cid.to_string(), None).await? {
            let announcement = Announcement::decode(&mut &content[..])?;
            return Ok(Some(announcement.data));
        }

        Ok(None)
    }

    // async fn remove(&self, cid: &Cid) -> Result<()> {
    //     self.doc
    //         .del(
    //             self.node.docs().author_default().await.unwrap(),
    //             cid.to_string(),
    //         )
    //         .await?;
    //     Ok(())
    // }
}

impl<C: Pairing> DocStore for IrohDocStore<C> {}
