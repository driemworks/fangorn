use crate::{backend::Backend, client::Node, types::*};
use anyhow::Result;
use ark_ec::pairing::Pairing;
use async_trait::async_trait;
use cid::Cid;
use iroh_docs::{
    api::Doc,
    store::{FlatQuery, QueryBuilder},
};

pub trait SharedIrohBackend: Backend<Doc, String, Vec<u8>> {}

pub struct IrohBackend<C: Pairing> {
    pub node: Node<C>,
}

impl<C: Pairing> IrohBackend<C> {
    pub fn new(node: Node<C>) -> Self {
        Self { node }
    }
}

impl<C: Pairing> SharedIrohBackend for IrohBackend<C> {}

#[async_trait]
impl<C: Pairing> Backend<Doc, String, Vec<u8>> for IrohBackend<C> {
    // todo: maybe we should somehow pass in the query builder instead as a generic?
    // also: This decodes announcements explicitly, is that what I want?
    async fn read(
        &self,
        doc: &Doc,
        key: &String,
        extras: Option<Vec<u8>>,
    ) -> Result<Option<Vec<u8>>> {
        let entry = doc
            .get_one(QueryBuilder::<FlatQuery>::default().key_exact(key).build())
            .await?;

        match entry {
            Some(e) => {
                let hash = e.content_hash();
                let content = self.node.blobs().get_bytes(hash).await?;
                Ok(Some(content.to_vec()))
            }
            None => Ok(None),
        }
    }

    async fn write(&self, doc: &Doc, key: &String, value: &Vec<u8>) -> Result<Vec<u8>> {
        let result = doc
            .set_bytes(
                self.node.docs().author_default().await.unwrap(),
                key.clone().into_bytes(),
                value.clone(),
            )
            .await?;

        Ok(result.as_bytes().to_vec())
    }
}
