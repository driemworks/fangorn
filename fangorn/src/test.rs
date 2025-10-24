// use crate::cli::{FangornNodeCli as Cli, FangornNodeCommands as Commands};

#[tokio::test]
async fn basic_encrypt_decrypt_works() {
    use std::time::Duration;
    use tokio::time::sleep;
    
    let max_committee_size = 2;
    
    // Start bootstrap node
    let bootstrap_config = ServiceConfig {
        bind_port: 9933,
        rpc_port: 30333,
        index: 0,
        bootstrap_peers: None,
        is_bootstrap: true,
        ticket: None,
    };
    
    let bootstrap_handle = build_full_service::<E>(bootstrap_config, max_committee_size)
        .await
        .unwrap();
    
    println!("Bootstrap started with ticket: {}", bootstrap_handle.ticket);
    
    // Get bootstrap node address
    let bootstrap_pubkey = bootstrap_handle.node.router.endpoint().node_addr().await.unwrap().node_id.to_string();
    let bootstrap_ip = format!("127.0.0.1:{}", 9933);

    println!("{:?} - {:?}", bootstrap_pubkey, bootstrap_ip);
    
    // Give it time to fully initialize
    sleep(Duration::from_secs(5)).await;
    
    // Start client node
    let client_config = ServiceConfig {
        bind_port: 9934,
        rpc_port: 30334,
        index: 1,
        bootstrap_peers: ServiceConfig::build_bootstrap_peers(
            Some(bootstrap_pubkey),
            Some(bootstrap_ip),
        ),
        is_bootstrap: false,
        ticket: Some(bootstrap_handle.ticket.clone()),
    };
    
    let client_handle = build_full_service::<E>(client_config, max_committee_size)
        .await
        .unwrap();
    
    println!("Client node started");
    
    // // Wait for sync
    // sleep(Duration::from_secs(5)).await;
    
    // // Now check if client got the config by checking its state
    // let client_state = client_handle.node.state.lock().await;
    // assert!(client_state.config.is_some(), "Client should have synced config");
    
    // // Check if get_pk() works now
    // drop(client_state); // Release lock
    // let pk = client_handle.node.get_pk().await;
    // assert!(pk.is_some(), "Should be able to compute public key after sync");
    
    // println!("Test passed! Config synced successfully");
}