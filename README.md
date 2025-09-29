# Silent Threshold Encryption PoC

This is a proof of concept of a distributed network that enables silent threshold encryption.

## Setup Guide

1. start a bootstrap node

cargo run -- run --bind-port 9944 --rpc-port 30333 --is-bootstrap --index 0

> This will save the randomly generated config to config.txt

2. start a second peer (copy/paste pubkey and ticket)

cargo run -- run --bind-port 9945 --rpc-port 30334 --bootstrap-pubkey faffe9c7183032237c8922c06742e43372f2e90cc728852a01ba78221f41f4ed --bootstrap-ip 172.31.149.62:9944 --ticket docaaaca46oxzfmt5nd6hwjo5647lhkpyndhxmuj2ugna4x23e7hkd2otnyah5p72ohdaydei34rermaz2c4qzxf4xjbtdsrbjkag5hqiq7ih2o2ajdnb2hi4dthixs65ltmuys2mjoojswyylzfzuxe33ifzxgk5dxn5zgwlrpaiagdmdehkkoqayavqpzkpwyju --index 1

#### Encrypt a message

> hardcoded to save to ciphertext.txt for now

cargo run -- encrypt --message "hello123123" --config-dir config.txt

#### Decrypt a message 

cargo run -- decrypt --ciphertext-dir ciphertext.txt --config-dir config.txt

## TODOs

- add proper keygen and secure keystore
- add x25519 support
  - X25519 + AES_GCM for encrypting partial decryptions
- investigate usage of a TEE for secure computations
- investigate secure partial decryption store
  - verify part decs + recover signature
- investigate usage of twine-rs
  - add CRDT support + verifable tixels
  - then we can use it for verifiable logging between nodes + for divulging partdecs
- add IPFS support
  - add ciphertexts to IPFS
  - read ciphertexts from IPFS
- investigate zk proving system
- investigate inclusion of blockchain light clients for proving states
  - start with Smoldot (Polkadot)
- investigate metadata storage system 
  - using iroh doc store
  - register via RPC?
  - [CID -> {CONDITION, OWNER}]
- separate the 'worker' functionality from encrypt/decrypt
- add wasm support for multi-language bindings (enc/dec in js for example)# iris
