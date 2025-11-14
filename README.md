# Fangorn


> "Certainly the forest of **Fangorn** is perilous — not least to those that are too ready with their axes; and Fangorn himself, he is perilous too; yet he is wise and kindly nonetheless.”
― J.R.R. Tolkien, The Lord of the Rings

Fangorn is a trustless, distributed and permissionless **silent threshold encryption** network that aims to accomplish general purpose 'practical' witness encryption. It uses [a breakthrough in threshold encryption](https://eprint.iacr.org/2024/263) to introduce a new paradigm, which we call `intent-bound data`. It allows data to be encrypted locally under an *intent* that must be satisfied for decryption to pass. Through an extensible **gadget** framework, our system allows for new mechanisms for *decentralized conditional access control* to be easily implemented and **composed** to form more complex statements. In the scope of the hackathon, we have implemented three gadgets:

- **password-gadget** - a minimalistic gadget implementation that allows data to be encrypted under a (one-time-use) password
- **psp22-gadget** - allows data to be encrypted such that knowledge of the public key of anyone owning at least a minimum balance of the token defined in the psp22 contract can decrypt the data
- **sr25519-gadget** - verify a schnorr signature

As stated, gadgets can be **composed** to build more complex statements. To demonstrate, by composing the psp2-gadget and sr25519 gadget, we achieve **token-gated content**. 

e.g. `Psp22(contract_address, min_balance) && Sr25519()`

It supports a modular and dynamic storage backend, which  can be customized for specialized plaintext locations, intent storage locations, and ciphertext download locations. 

- Dependencies and technologies used
  - describe silent threshold encryption 
  - iroh for networking
  - ink! smart contracts
  - substrate-contracts-node

- todo: make some diagrams? can also do a long form doc on architecture, ste, etc., would be good for the demo
- todo: describe gadgets + intents, [link to gadgets readme](./fangorn/src/gadget/README.md)

- See the [setup guide](./docs/setup.md) to learn how to run Fangorn.

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

### NFT Types priveleges
1. Perpetual NFTs: An NFT that allows data access in perpetuity. So long as the ciphertext is accessible, users who own this NFT can access that data.
  Use cases: Privileged roles and access management (admin, executive, developer,...), personal data ownership (music albums, movies, tv shows)
2. Time gated NFTs: An NFT that allows data access over a period of time. Once time expires data access is lost.
  Use cases: Temporary priveleged roles and access managent. Licensing of data (streaming services?)
3. N-time access NFTs: An NFT that allows data access a total number of N times. Once data has been accessed N times using that NFT, data access is lost.
  Use cases: IDK but I bet someone creative can come up with something :p
4. Revokable Access Tokens
---

Password
Psp22-Ownership
Signature

---

DaoMembership
Time
GPS (as a password)
API & Verification logic => gadget 
proof-of-x: `it rained in Dallas on sunday according to weather.com`

=> wrap them all in zkps (e.g. circom)

----

#### TODOs

- RPC
- Merkle Verifier - maybe not for hackathon, future work
- IPFS integration (or polkastorage or something to give more oomph?) - also future work? can use firebase for now if need be, though will try to stretch. 

- [ ] design smart contract, deploy on IDN? Asset Hub? 
- [ ] Gossipsub for requesting partial decryptions
- [ ] masking partial decryptions and unmasking 
- [ ] user interface design