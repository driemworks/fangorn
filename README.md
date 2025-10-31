# Fangorn 

"Certainly the forest of Fangorn is perilous — not least to those that are too ready with their axes; and Fangorn himself, he is perilous too; yet he is wise and kindly nonetheless.”
― J.R.R. Tolkien, The Lord of the Rings 

## Setup Guide

0. Build the binaries

From the root, run `cargo build`.

### Option A: Manually starting the instances
1. start a bootstrap node

    ./target/debug/fangorn run --bind-port 9944 --rpc-port 30333 --is-bootstrap --index 0

> This will save the randomly generated config to config.txt

2. start a second peer (copy/paste pubkey and ticket)
    > Note: pubkey is written to pubkey.txt and ticket is written to ticket.txt

    ./target/debug/fangorn run --bind-port 9945 --rpc-port 30334 --bootstrap-pubkey d5241466abbd753d3124416dceaf8e96b806fa5f1c4cc816cea432393e09437d --bootstrap-ip 172.31.149.62:9944 --ticket docaaacbb5qoi6exqm2tzh3eqqb6zap2jmppocn3udv3qvbpz7jwvnnzpc7ahksifdgvo6xkpjreraw3tvpr2llqbx2l4oezsawz2sdeoj6bfbx2ajdnb2hi4dthixs65ltmuys2mjoojswyylzfzuxe33ifzxgk5dxn5zgwlrpaiagdmdehlnomayavqolfpoyju --index 1

### Option B: Automatically start two instances
1. Ensure start_instances.sh has execute priveleges: `chmod +x start_servers.sh`
2. From the root, run start_instances.sh: `./start_instances.sh`

#### Using Quickbeam
##### Encrypt a message 

> hardcoded to save to ciphertext.txt for now
> you must delete the file if you want to encrypt a new message... needs work

./target/debug/quickbeam encrypt --message-dir test.txt --config-dir config.txt --intent "Password(test)"

##### Decrypt a message 

./target/debug/quickbeam decrypt --cid bafkreidkaj2d7ken3jfhs4sbgylgvvr2yorif7eqv3plt7nq6iq4txw27m --config-dir config.txt

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
- add wasm support for multi-language bindings (enc/dec in js for example)# iris


### Hackathon Scope

#### Project Name
Iris: Intent-Bound Data on Polkadot

Track: Track 1 - dApp Track?
Track: Track 3 - tinkerer track?

#### Description

Intent-bound data is revolutionizes access control for web3.

Today, web3 is capable of handling cryptographically provably ownership and identity, yet it lacks clear access control mechanisms. 

The social and economic impact: streaming services require subscriptions to entire databases and curated servcies rather, with actual artists and creators being unable to sell content for fair market prices. Instead, if creators are unable to license content through a studio, they are instead are restricted  to unreliable rewards through platforms like YouTube, Patreon, or even OnlyFans. Here,  their hard work may reward them, but the systems are inherently designed to reward the platform providers: they are, irrefutably and by design, *exractive* technologies. They monetize peoples' willingness to share and communicate with others by turning users into a product. No ads become 5 second ads become unskippable 10 seconds ads become you being a commodity. Services like Spotify, initially a godsend for digital artists, has since become exploitative, with musicians seeing pennies but illegitimate AI artists unduly profiting by pleasing the algorithm. With the latest sora2 launch, this kind of AI-generated rot, slop, or gold will obliterate the profits and revenue of real human creators. While this could initially be seen as easy wins for many -- generate slop and profit -- it ultimately aims to stagnate and diminish creative output. 

Instead of relying on centralized systems to act as arbiters of data access, threshold encryption and zero knowledge cryptography can be leveraged to enable access by mathematical proof, not by permission. Iris uses breakthroughts in threshold cryptography that allow for the network to function in the absence of trusted setup via distributed key generation (DKG) while enabling internet-scale threshold encryption capabilities. Rather than rely on platforms and permissions to gate access to data, Iris is an open protocol where content owners can determine not only who, but *how* their data can be accessed. 

##### Key Features
- decentralized access control
- censorship resistance
- ransomware resistance

The general idea:
Access control in a smart contract

1. Encrypt data under a policy P -> add to IPFS -> publish in Iris
2. Satisfy policy (witness) -> build proof -> request data access
3. verify proof -> provide partial decryption
4. aggregate and decrypt

e.g. a user flow could be...
Seller:
- I wrote a book and want to sell it. If you buy my NFT then you should get access.
- I want to publish it once and then be able to go offline forever while still reaping benefit when copies are sold.
Buyer: If I buy your book for $X, then I own it. I do not want to pay more fees to read it - I just pay one fee and am done forever.

#### TODOs

- RPC
- Merkle Verifier - maybe not for hackathon, future work
- IPFS integration (or polkastorage or something to give more oomph?) - also future work? can use firebase for now if need be, though will try to stretch. 

- [ ] design smart contract, deploy on IDN? Asset Hub? 
- [ ] Gossipsub for requesting partial decryptions
- [ ] masking partial decryptions and unmasking 
- [ ] user interface design