use crate::{crypto::decrypt::*, node::Node, types::*};
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
use n0_future::StreamExt;

pub trait RpcAddressResolver {
    // look up the public IP:Port for a given node id
    #[allow(async_fn_in_trait)]
    async fn resolve_rpc_address(&self, node_id: usize) -> Result<String, DecryptionClientError>;
}

pub struct IrohRpcResolver {
    pub doc_stream: Doc<FlumeConnector<Response, Request>>,
    pub node: Node<E>,
}

impl RpcAddressResolver for IrohRpcResolver {
    // todo: fix this later
    #[allow(async_fn_in_trait)]
    async fn resolve_rpc_address(&self, node_id: usize) -> Result<String, DecryptionClientError> {
        let key = format!("{}{}", RPC_KEY_PREFIX, node_id);
        let rpc_query = QueryBuilder::<FlatQuery>::default().key_exact(key).limit(1);

        let entry_list = self
            .doc_stream
            .get_many(rpc_query.build())
            .await
            .map_err(|e| DecryptionClientError::LookupError(e.to_string()))?;
            
        let entry = entry_list.collect::<Vec<_>>().await;

        if let Some(Ok(entry)) = entry.into_iter().next() {
            let hash = entry.content_hash();
            let content =
                self.node.blobs().read_to_bytes(hash).await.map_err(|e| {
                    DecryptionClientError::LookupError(format!("Blob error: {}", e))
                })?;

            // content is the public RPC address string
            String::from_utf8(content.to_vec()[2..].to_vec())
                .map_err(|e| DecryptionClientError::LookupError(format!("UTF8 error: {}", e)))
        } else {
            Err(DecryptionClientError::MissingRpcAddress(node_id))
        }
    }
}
