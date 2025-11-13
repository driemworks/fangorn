# FANGORN

---

**Hackathon**: link
**Track**: 3 - Polkadot Tinkerers
**Team**: Tony Riemer & Coleman Irby

---

[TODO: embed demo here]

## The Platform Problem

The "platform-economy" [1](https://www.ebsco.com/research-starters/technology/platform-economy) is just any economic activity conducted on platforms. Today, >80% of the top performing companies globally are part of the platform economy (e.g. Microsoft, Apple, Nvidia, Alphabet, Meta ). While "many business experts see the platform economy as increasing productivity" and making businesses more efficient and this is not untrue. Over the last two decades, big tech has transformed the global economy, but it comes at a cost.

### Big Tech's Rent-Seeking Behavior

Platforms often engage in rent-seeking behaviors where they rely on manufactured scarcity to extract value from their users and increase their capital. 

There is an identifiable pattern that big-tech companies often follow [1](https://www.linkedin.com/pulse/big-tech-rise-economic-rent-seeking-abhay-gupta-ph-d--gzwfc/):

1. Innovate & Disrupt - Create real value and disrupt existing markets (e.g. Google Search, the iPhone)
2. User Lock-in - Leverage network effects, make it expensive or painful to switch to other services or stop using it (Google tightly bundling services, all your friends are on Facebook)
3. Extraction - Collect user data and monetize it without compensation or explicit consent (surveillance, monitoring users' behavioral patterns, reading from the clipboard, targeted ads)
4. Gatekeeping - Control access with manufactured scarcity and charge rent (app stores charge developer fees, Spotify takes 70% of artist revenue, pay to get ahead in proprietary, black-box algorithms to promote content).

In the final step, platforms extract fees for access to markets they didn't create, using control they didn't earn through innovation. 

The internet promised was "disintermediation" [2](https://doctorow.medium.com/big-techs-attention-rents-fe97ba3fad90) (getting rid of intermediaries), but then produced new intermediaries. When a single entity dominates an informational landscape (e.g. Google controls 90% of searches), then the way information is displayed can "deprive you access to information without you knowing it". If you never see a social media update from a news source you follow, you might simply forget about it. If you only see one kind of media, then you will be inclined to believe it. That is, this form of surveillance capitalism breeds platform decay through the pattern identified above. This is often called Enshittification: a modern, high-tech enabled, monopolistic form of **rent seeking**. 

"The point of enshittification is to lock end-users to the platform, then use those locked-in users as bait for business customers, who will also become locked to the platform. Once everyone is holding everyone else hostage, the platform uses the flexibility of digital services to play a variety of algorithmic games to shift value from everyone to the business’s shareholders."

### You'll own nothing and be happy

This is a controversial phrase in a paper [published by the WEF in 2016](https://en.wikipedia.org/wiki/You%27ll_own_nothing_and_be_happy) that explored a future where humanity relies on a 'sharing economy' for their needs. This idea has seen a lot of opposition [3](https://capitalresearch.org/article/they-really-believe-youll-be-happy/). However, without realizing it, most people are already participating in this style of economy. 

You "bought" an album on iTunes. Apple lost the licensing. You lost the album.

You own an NFT for an in-game item. The game shuts down. Your asset is worthless, as the true value existed in their servers.

Even worse, platforms impose rent by manufacturing **digital scarcity**. Data, unlike oil, is infinitely replicable. Platforms create artificial scarcity by **controlling access**, then monetize that control.

- Streaming services provide *permission* to access a collection
- Apple charges 30% to distribute apps
- Uber engages in [algorithmic wage discrimination](https://www.columbialawreview.org/content/on-algorithmic-wage-discrimination/)

Even worse, when platforms do not engage in rent-seeking behavior, they are still gatekeepers of data. This makes them high-value targets by external actors to try to exploit them as well. For example, hospitals are hit with ransomeware attacks quite frequently. 

### Web3's Incomplete Revolution

Web3 gave us cryptographic identity and ownership proofs, but ownership of what?

Decentralized Identity != Decentralized Access Control.

When an NFT simply references a CID, you really only own the association: this NFT id maps to this CID. You don't 'own' the storage location. If the content is in IPFS and becomes unpinned, it's even possible that it can't be recovered later. Ownership of the on-chain asset does not correlate to ownership of the associated data. Largely, due to hype-driven marketing like BAYC, NFTs are seen as simply a meme in the wider non-crypto culture (and they're not wrong), with no intrinsic value or reason to exist. 

While DIDs can logically gate access, content is still on centralized servers. The phrase "not your keys, not your crypto" is often said in terms of custodial v.s. non-custodial crypto wallets. The same applies to your data. Not your keys, not your data. While legislation and regulation exists, they cannot inherently stop exploitation of user data.

## The Solution: Decentralized Conditional Access Control

While regulations like the EU's [Digital Markets Act](https://digital-markets-act.ec.europa.eu/about-dma_en) attempt to regulate this kind of gatekeeping, Fangorn seeks to **eliminates** it. With no platform, there is no rent to extract. While regulation can impose fines on rent-seeking behavior, it does not eliminate it. If fines are not significant enough, then it is simply the cost of business (operational overhead). 

Fangorn introduces the idea of 'intent-bound data'. This is a new paradigm where data owners encrypt data locally under an *intent*. This is a form of 'practical' *witness encryption*. It enables new mechanisms for conditional access control through an extensible "gadget" framework. 

Today, if an author wants to publish their book, they rely on traditional, centralized services. These gatekeepers hold all the keys and provide *permission* to access, but do not offer real ownership or control. Generally, data is encrypted for the server's public key alone. **Witness encryption** is a type of encryption scheme where data is encrypted for **provable conditions**, with decryption possible only if you can satisfy the condition. 

### The Innovation: Silent Threshold Encryption

### Polkadot-Native Integration

### Existing Solutions

- especially need to compare to LIT protocol

### Potential Impact
