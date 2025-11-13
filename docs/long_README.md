# FANGORN

---

- **Hackathon**: https://polkadot.devpost.com/
- **Track**: 3 - Polkadot Tinkerers
- **Team**: Tony Riemer & Coleman Irby
- **Github**: 
  - Fangorn repo: https://github.com/driemworks/fangorn
  - Silent-Threshold-Encryption repo: https://github.com/driemworks/silent-threshold-encryption/tree/dev
- **Description**: Decentralized Conditional Access Control: Encrypt data under provable conditions, decrypted by a trustless network.

---

[TODO: embed demo here]

## The Platform Problem

The "platform-economy" [[1]](https://www.ebsco.com/research-starters/technology/platform-economy) is just any economic activity conducted on platforms. Today, >80% of the top performing companies globally are part of the platform economy (e.g. Microsoft, Apple, Nvidia, Alphabet, Meta ). While "many business experts see the platform economy as increasing productivity" and making businesses more efficient and this is not untrue. Over the last two decades, big tech has transformed the global economy, but it comes at a cost.

### Big Tech's Rent-Seeking Behavior

Platforms often engage in rent-seeking behaviors where they rely on manufactured scarcity to extract value from their users and increase their capital. 

There is an identifiable pattern that big-tech companies often follow [[2]](https://www.linkedin.com/pulse/big-tech-rise-economic-rent-seeking-abhay-gupta-ph-d--gzwfc/):

1. Innovate & Disrupt - Create real value and disrupt existing markets (e.g. Google Search, the iPhone)
2. User Lock-in - Leverage network effects, make it expensive or painful to switch to other services or stop using it (Google tightly bundling services, all your friends are on Facebook)
3. Extraction - Collect user data and monetize it without compensation or explicit consent (surveillance, monitoring users' behavioral patterns, reading from the clipboard, targeted ads)
4. Gatekeeping - Control access with manufactured scarcity and charge rent (app stores charge developer fees, Spotify pays out little, pay-to-play against proprietary, black-box algorithms, etc).

In the final step, platforms extract fees for access to markets they didn't create, using control they didn't earn through innovation. 

The internet promised "disintermediation" [[3]](https://doctorow.medium.com/big-techs-attention-rents-fe97ba3fad90) (getting rid of intermediaries), but then produced new intermediaries. When a single entity dominates an informational landscape (e.g. Google controls 90% of searches), then the way information is displayed can "deprive you access to information without you knowing it". If you never see a social media update from a news source you follow, you might simply forget about it. If you only see one kind of media, then you will be inclined to believe it. That is, this form of surveillance capitalism breeds platform decay through the pattern identified above. This is often called Enshittification: a modern, high-tech enabled, monopolistic form of **rent seeking**. 

"The point of enshittification is to lock end-users to the platform, then use those locked-in users as bait for business customers, who will also become locked to the platform. Once everyone is holding everyone else hostage, the platform uses the flexibility of digital services to play a variety of algorithmic games to shift value from everyone to the business’s shareholders."

### You'll own nothing and be happy: Digital Rentiership

This is a controversial phrase in a paper [published by the WEF in 2016](https://en.wikipedia.org/wiki/You%27ll_own_nothing_and_be_happy) that explored a future where humanity relies on a 'sharing economy' for their needs. This idea has seen a lot of opposition [[4]](https://capitalresearch.org/article/they-really-believe-youll-be-happy/). However, without realizing it, most people are already participating in this style of economy. Today, five of the largest corporations in the world are digital technology firms. From digital search, social networks, smartphones, online markets, advertising, media and more, these firms own and dictate access control to products, services, and infrastructure that we increasingly rely on in everyday life [4](https://www.tandfonline.com/doi/epdf/10.1080/09505431.2021.1932794?needAccess=true).

- You "bought" an album on iTunes. Apple lost the licensing. You lost the album.
- You own an NFT for an in-game item. The game shuts down. Your asset is worthless, as the true value existed in their servers.
- You paid for a movie but don't have the proper DRM client installed, so you can't watch it.

The issue extends beyond the purely digital. Maybe you are a farmer and bought a John Deere tractor, but must rely on the company for repairs [[5]](https://www.nbcnews.com/business/consumer/right-to-repair-farmers-challenge-john-deere-control-equipment-rcna199651). You bought a printer but you must use their proprietary ink cartdidges. The list goes on and on.

Even worse, platforms impose rent by manufacturing **digital scarcity**. Data, unlike oil, is infinitely replicable. Platforms create artificial scarcity by **controlling access**, then monetize that control.

- Streaming services provide *permission* to access a collection
- Apple charges 30% to distribute apps
- Uber engages in [algorithmic wage discrimination](https://www.columbialawreview.org/content/on-algorithmic-wage-discrimination/)

Even when platforms do not engage in rent-seeking behavior, they are still gatekeepers of data. This makes them high-value targets by external actors to try to exploit them as well. For example, hospitals are hit with ransomeware attacks quite frequently. 

### Web3's Incomplete Revolution

Web3 gave us cryptographic identity and ownership proofs, but ownership of what?

Decentralized Identity != Decentralized Access Control.

When an NFT references a CID, you really only own the association: this NFT id maps to this CID. You don't own the storage location; you don't own the bytes. If the content is in IPFS and becomes unpinned, it's even possible that it can't be recovered later. Ownership of the on-chain asset does not correlate to ownership of the associated data. Largely, due to hype-driven marketing like BAYC, NFTs are seen as simply a meme in the wider non-crypto culture (and they're not wrong), with no intrinsic value or reason to exist. 

While DIDs can logically gate access, content is still on centralized servers. The phrase "not your keys, not your crypto" is often said in terms of custodial v.s. non-custodial crypto wallets. The same applies to your data. Not your keys, not your data. While legislation and regulation exists, they cannot inherently stop exploitation of user data. While the natural response to a 10 meter tall wall is an 11 meter ladder,  tech companies often lobby the government for preferential treatment, passing unfair laws (like 'anticircumvention laws') that make the 11-meter ladder *illegal* [[6]](https://doctorow.medium.com/https-pluralistic-net-2025-05-14-pregnable-checkm8-d6dad704c5c9).

General data is, still to this day, usually secured using *digital locks* - legally enforced 'locks' that let Apple block third party repairs, or let your printer reject third party ink replacements, but which don't actually 'work'. The design theory of these kinds of locks, e.g. [Digital Rights Management](https://en.wikipedia.org/wiki/Digital_rights_management), is to run proprietary software on the user's device (e.g. the [widevine content decryption module](https://bunny.net/academy/streaming/what-is-widevine-cdm-content-decryption-module/)). Essentially, this means there is a hidden secret key *not owned by you* that **lives on your device** that is illegal to access! How fun.

## The Solution: Decentralized Conditional Access Control

While regulations like the EU's [Digital Markets Act](https://digital-markets-act.ec.europa.eu/about-dma_en) and Canada's [CPPA](https://www.justice.gc.ca/eng/csj-sjc/pl/charter-charte/c27_1.html) attempt to regulate this kind of gatekeeping, Fangorn seeks to **eliminate** it. With no platform, there is no rent to extract. While regulation can impose fines on rent-seeking behavior, it does not eliminate it. If fines are not significant enough, then it is simply the cost of business (operational overhead). 

Fangorn is a trustless, distributed and permissionless **silent threshold encryption** network that aims to accomplish general purpose 'practical' witness encryption. It uses [a breakthrough in threshold encryption](https://eprint.iacr.org/2024/263) to introduce a new paradigm, which we call `intent-bound data`. It allows data to be encrypted locally under an *intent* that must be satisfied for decryption to pass. Through an extensible **gadget** framework, our system allows for new mechanisms for *decentralized conditional access control* to be easily implemented and **composed** to form more complex statements. In the scope of the hackathon, we have implemented three gadgets:

- **password-gadget** - a minimalistic gadget implementation that allows data to be encrypted under a (one-time-use) password
- **psp22-gadget** - allows data to be encrypted such that knowledge of the public key of anyone owning at least a minimum balance of the token defined in the psp22 contract can decrypt the data
- **sr25519-gadget** - verify a schnorr signature

As stated, gadgets can be **composed** to build more complex statements. To demonstrate, by composing the psp2-gadget and sr25519 gadget, we achieve **token-gated content**. 

e.g. `Psp22(contract_address, min_balance) && Sr25519()`

### The Innovation: Practical Witness Encryption 

Today, if an author wants to publish their book, they generally rely on traditional, centralized services. These gatekeepers hold all the keys and provide *permission* to access, but do not offer real ownership or control. Generally, data is encrypted for the server's public key alone. **Witness encryption** is a type of encryption scheme where data is encrypted for **provable conditions**, with decryption made possible if and only if you can satisfy the condition by providing a **witness**.

At a high level, given an *NP-relation* $R \in \{0, 1\}^*$, a message can be encrypted under a *statement* $s$. For a *witness* $w$, we say it is valid if $(w, s) \in R$. In other words, it lets you encrypt data under a *statement* that acts like the public key, no secret key needed. For example, a statement could be "I know the preimage of 0x01234567...", with the witness being 'some secret string' where Hash('some secret string') = 0x01234567....

A **gadget** in Fangorn acts as the NP-relation that determines *how* statements and witnesses are associated with each other. That is, is takes the role of the NP-relation $R$ above. And **intent** is mapped, via gadgets, to a **statement** that the gadget can use to verify a witness later on. Users make requests to workers for decryption by providing 

### The Cryptographic Breakthrough: Silent Threshold Encryption

Fangorn's core protocol is empowered by [threshold encryption with silent setup](https://eprint.iacr.org/2024/263). Critically, it allow sus to securely encrypt data under complex, provable conditions without relying on a centralized authority or coordinator.

> We interfaced directly with the team behind the research and augmented the academic proof of concept to productionalize it, introduce error handling, and more. You can find our fork [here](https://github.com/driemworks/silent-threshold-encryption/tree/dev)

#### What is Threshold Encryption? 

Threshold encryption splits decryption power across many parties, so no single party can decrypt alone.

Intuitively, it’s like a vault that needs t out of n keys to open (t <= n), e.g. 3 out of 5. Each committee member holds one key, or a “share”. They each use their key to create a “partial decryption” (like partially turning the lock). When >= t partial decryptions combine, the full plaintext is revealed. Until then, contents are completely hidden.

#### Silent Threshold Encryption

*Silent* threshold encryption operates as a **special purpose witness encryption scheme** for verifying signatures which provides the basis for our gadget framework. Normally, threshold encryption schemes require a **distributed key generation** (DKG) algorithm, involving complex a setup protocol and communication overhead. Threshold encryption networks like LIT, or threshold signing networks like Drand (randomness beacons output BLS signatures), must periodically engage in key rotation *ceremonies*, especially if the underlying set of workers/key holders changes. STE, on the other hand, allows for the network 

### Polkadot-Native Integration

- Substrate & ink!:
  - Our network operates against a Substrate-based backend that supports ink! smart contracts, where we deploy a permisionless **intent registry** contract. The intent registry enables filenames to be associated with intents, acting as a secure document registry in a smart contract. 
  - Our solution relies on the Psp22 token standard.
- Extensible Gadget Framework - Our extensible gadget framework allows for new new intents to be defined and composed. For the hackathon, we implemented password, psp22, and and Schnorr signature gadgets that can be composed to create more powerful statement, like **token gated content**. 

### Existing Solutions

TODO

- compare to proxy-reencryption 
- especially need to compare to LIT protocol

### Potential Impact

TODO

- true digital ownership
- censorship-resistant distribution
- ransomware-resistant data
- novel capabilities for web3:
  - secure data marketplaces
  - can build spotify-on-web3
  - etc...

### Qs/misc

Ok but why threshold encryption?