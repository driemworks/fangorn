# Fangorn

> "Certainly the forest of Fangorn is perilous — not least to those that are too ready with their axes; and Fangorn himself, he is perilous too; yet he is wise and kindly nonetheless.”
― J.R.R. Tolkien, The Lord of the Rings

Fangorn is a p2p threshold encryption network that enables 'practical' witness encryption. 
It enables decentralized conditional access control for generic data sets.

It provides a mechanism to encrypt data for an *intent* (e.g. you must know the preimage of Sha256(_password_)), with decryption being allowed when a valid *witness* (e.g. the password) is provided. 

It supports a modular and dynamic storage backend, which  can be customized for specialized plaintext locations, intent storage locations, and ciphertext download locations. 

It boasts an extensible *gadgets* module that allows for the implementation of new gadgets.

- Dependencies and technologies used
  - describe silent threshold encryption 
  - iroh for networking
  - ink! smart contracts
  - substrate-contracts-node


- todo: describe gadgets + intents, [link to gadgets readme](./fangorn/src/gadget/README.md)


## Setup Guide

This is a guide to run fangorn locally.

### Prerequisites (One Time Setup)

1. [Install cargo contract](https://github.com/use-ink/cargo-contract)
2. Build the 'iris' contract locally (from the root):
   ``` sh
   cd contracts/iris
   cargo contract build --release
   ```

3. Install the substrate contracts node: `cargo install contracts-node`. It can be run locally by running `substrate-contracts-node`, starting the contracts node on port 9944 by default.
4. Then, from the project root, generate metadata with `subxt metadata --url ws://localhost:9944 > metadata.scale`
5. Tear down the contracts node, then build the binaries. From the root, run: `cargo build`.

### Build a Network

You must run a minimum of 2 Fangorn nodes, with a maximum of 255 (arbitary and untested).
 
For a modular approach (e.g. to setup a node on a dedicated machine), follow [option A](#option-a-manually-starting-the-instances).

For a quick start that runs everything locally, follow [option B](#option-b-automatically-start-two-instances).

#### Option A: Manually starting the instances
##### Substrate Contracts Node Setup
1. Start the substrate-contracts-node again: `substrate-contracts-node` and deploy the `iris` contract with 
   `cargo contract instantiate ./target/ink/iris/iris.contract --suri //Alice -x -y`
2. Copy the contract address (e.g. `5CCe2pCQdwrmLis67y15xhmX2ifKnD8JuVFtaENuMhwJXDUD`)
3. start a bootstrap node

``` sh
    ./target/debug/fangorn run \
    --bind-port 9933 \
    --rpc-port 30332 \
    --is-bootstrap \
    --index 0  \
    --contract-addr "5CCe2pCQdwrmLis67y15xhmX2ifKnD8JuVFtaENuMhwJXDUD"
```

> This will save the randomly generated config to config.txt

4. start a second peer (copy/paste pubkey and ticket)
    > Note: pubkey is written to pubkey.txt and ticket is written to ticket.txt

``` sh
    ./target/debug/fangorn run \
    --bind-port 9945 
    --rpc-port 30334 \
    --bootstrap-pubkey 2ec177c3b8442215520052b55d2f9cef09ae0a65d35769a3f63b3659c099ccb2 \
    --bootstrap-ip 172.31.149.62:9944 \
    --ticket docaaacbsx4px23g66nfvyg4olvhsbm4s4477sj6c4b33lutfev6ym4ap7iaexmc56dxbccefksabjlkxjpttxqtlqkmxjvo2nd6y5tmwoathgleajdnb2hi4dthixs65ltmuys2mjoojswyylzfzuxe33ifzxgk5dxn5zgwlrpaiagd55ruhj52ayavqolfponju \
    --index 1 \
    --contract-addr "5CCe2pCQdwrmLis67y15xhmX2ifKnD8JuVFtaENuMhwJXDUD"
```

#### Option B: Automatically start two instances
0. Install gnome-terminal `sudo apt install gnome-terminal`
1. Ensure start_instances.sh has execute priveleges: `chmod +x start_servers.sh`
2. From the root, run start_instances.sh: `./start_instances.sh`
 
### Using Quickbeam

Quickbeam is a basic CLI for generating keys, signing messages, and encryption/decryption. 

##### Generate a new keypair

> Note: for now we just take the first file in the keystore directory and try to use it as the seed
> when encrypting a file, so you can only have one key in the store at a time right now

``` sh
./target/debug/quickbeam keygen --keystore-dir tmp/keystore
```

#### Inspect keys


``` sh
./target/debug/quickbeam inspect --keystore-dir tmp/keystore
```

#### Sign a Message (nonce)

``` sh
./target/debug/quickbeam sign --keystore-dir tmp/keystore --nonce 0
```

##### Encrypt a message 

e.g. using the password intent

``` sh
./target/debug/quickbeam encrypt \
--message-path test.txt \
--filename test.txt \
--config-path config.txt \
--keystore-dir tmp/keystore \
--intent "Password(test)" \
--contract-addr "5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7"
```

e.g. using the Psp22 intent

> note: you must manually deploy and configure the psp22 contract address 

``` sh
./target/debug/quickbeam encrypt \
--message-path test.pdf \
--filename test.pdf \
--config-path config.txt \
--keystore-dir tmp/keystore \
--intent "Psp22(5DiTZLwsFHd19DQcQeYrCA67LKXbarXk3HBp9NWEsA43Mpp4, 1)" \
--contract-addr "5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7"
```


e.g. for sr25519 signatures

``` sh
./target/debug/quickbeam encrypt \
--message-path test.txt \
--filename test.txt \
--config-path config.txt \
--keystore-dir tmp/keystore \
--intent "Sr25519()" \
--contract-addr "5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7"
```

##### Decrypt a message 

e.g. Using the password intent (create a test.txt locally)

``` sh
./target/debug/quickbeam decrypt \
--filename test.txt \
--config-path config.txt \
--witness test \
--pt-filename test.txt \
--contract-addr "5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7"
```

e.g. using the Psp22 intent

> Don't forget to mint a token first!

``` sh
./target/debug/quickbeam decrypt \
--filename test.pdf \
--config-path config.txt \
--witness 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY \
--pt-filename test.pdf \
--contract-addr 5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7
```

e.g. sr25519 signatures

First produce a valid sr25519 signature on the message (acct_nonce).

``` sh
./target/debug/quickbeam decrypt \
--filename test.txt \
--config-path config.txt \
--witness "5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK38e819e577a476bd3bb9cd2c5e5521a499cd4a0e0a896f8ecb091c6579278923d52c3f579c854d5f0ba76b6e0266eb8851d7bbfb7c59c70cb036678714146c48d" \
--pt-filename test.txt \
--contract-addr "5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7"
```

### Entmoot

Entmoot is a TUI for interacting with Fangorn. It is similar to quickbeam, but provides better UX. 

1. From the root run: `cargo run -p entmoot`

2. To quit hit the ESC key

### Hackathon Scope

#### Project Name
Fangorn

Track: Track 1 - dApp Track?
Track: Track 3 - tinkerer track?

-  contracts are built using https://forum.polkadot.network/t/pendzl-a-smart-contract-library/5975

#### Description
Fangorn is a p2p threshold encryption network that enables 'practical' witness encryption. 

It enables decentralized conditional access control for generic data sets.

It acts as a decentralized key management system for Polkadot. 
Unlike LIT: 
- more decentralized, permissionless + open protocol

Intent-bound data is revolutionizes access control for web3.

This is a tool for a post-platform economy for:
- digital property rights: own what you buy instead of renting access. 
- creatory soverignty: truly control content distribution, not platforms
- user privacy: no databases, no tracking, no data collection
- permissionless & decentralized: can't be shut down, censored, or controlled
- convivial tech: value flows to creators and consumers, not parasitic intermediaries
- resilience: no 'company' that can mishandle the data, no platform to enshittify

"Same UX as piracy, but creators get paid."

Today, web3 is capable of handling cryptographically provably ownership and identity, yet it lacks clear access control mechanisms. 

The internet and all its connected apps and services are a place for corporations to collect and sell data, to get you hooked on their services, engage in their culture wars and practices. The magic of the early internet is extinct. The fun has been sucked away, but we still spend all of our time there. 

As Camus says: what does any artist truly strive for? global connection and understanding. While the internet stood to be an artform enabling unbounded creativity and understanding that crosses borders, it has largely failed. 

The social and economic impact: streaming services require subscriptions to entire databases and curated servcies rather, with actual artists and creators being unable to sell content for fair market prices. Instead, if creators are unable to license content through a studio, they are instead are restricted  to unreliable rewards through platforms like YouTube, Patreon, or even OnlyFans. Here,  their hard work may reward them, but the systems are inherently designed to reward the platform providers: they are, irrefutably and by design, *exractive* technologies. They monetize peoples' willingness to share and communicate with others by turning users into a product. No ads become 5 second ads become unskippable 10 seconds ads become you being a commodity. Services like Spotify, initially a godsend for digital artists, has since become exploitative, with musicians seeing pennies but illegitimate AI artists unduly profiting by pleasing the algorithm. With the latest sora2 launch, this kind of AI-generated rot, slop, or gold will obliterate the profits and revenue of real human creators. While this could initially be seen as easy wins for many -- generate slop and profit -- it ultimately aims to stagnate and diminish creative output. 

Instead of relying on centralized systems to act as arbiters of data access, threshold encryption and zero knowledge cryptography can be leveraged to enable access by mathematical proof, not by permission. Iris uses breakthroughts in threshold cryptography that allow for the network to function in the absence of trusted setup via distributed key generation (DKG) while enabling internet-scale threshold encryption capabilities. Rather than rely on platforms and permissions to gate access to data, Iris is an open protocol where content owners can determine not only who, but *how* their data can be accessed. 

##### Key Features
- decentralized access control
- censorship resistance
- ransomware resistance

### Use Cases

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

### NFT Types
NFTs define data access priveleges
1. Perpetual NFTs: An NFT that allows data access in perpetuity. So long as the ciphertext is accessible, users who own this NFT can access that data.
  Use cases: Privileged roles and access management (admin, executive, developer,...), personal data ownership (music albums, movies, tv shows)
2. Time gated NFTs: An NFT that allows data access over a period of time. Once time expires data access is lost.
  Use cases: Temporary priveleged roles and access managent. Licensing of data (streaming services?)
3. N-time access NFTs: An NFT that allows data access a total number of N times. Once data has been accessed N times using that NFT, data access is lost.
  Use cases: IDK but I bet someone creative can come up with something :p
4. Revokable Access Tokens

Password
Psp22-Ownership
Signature
DaoMembership
Time
GPS (as a password)
API & Verification logic => gadget 
proof-of-x: `it rained in dallas on sunday according to weather.com`

=> wrap them all in zkps (e.g. circom)

#### TODOs

- RPC
- Merkle Verifier - maybe not for hackathon, future work
- IPFS integration (or polkastorage or something to give more oomph?) - also future work? can use firebase for now if need be, though will try to stretch. 

- [ ] design smart contract, deploy on IDN? Asset Hub? 
- [ ] Gossipsub for requesting partial decryptions
- [ ] masking partial decryptions and unmasking 
- [ ] user interface design