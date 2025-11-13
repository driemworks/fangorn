# Intents & Gadgets

An **intent** is simply raw user input. By defining appropriate 'gadgets', we define a modular intent framework, where new kinds of intents, with unique parsing logic and features, can be easily introduced.

A **gadget** can perhaps be best explained by first defining witness encryption. 

---
Given an NP-relation $R \in \{0, 1\}^*$, for any pair $(x, w) \in R$, we call $x$ the statement and $w$ the witness. A witness encryption scheme associated with the relation $R$ is the algorithms $(WE.Enc, WE.Dec)$ such that:

- $ct \xleftarrow{R} WE.Enc(x, m)$ for a message $m \in \{0, 1\}^*$
- $m = WE.Enc(ct, w)$ where $w$ is a valid witness such that $(x, w) \in R$
---

In this context, a **gadget** acts like the NP-relation $R$. It is a machine that converts a user *intent* into an *NP-statement* against which users can provide *witnesses* for *verification*. It dicates the rules that Fangorn workers use when verifying witnesses, enabling programmable access control. 

The **gadget registry** allows for the composition of multiple gadgets within a Fangorn node (also: for encryption rules).

## Create a Gadget

The gadget framework is extensible. Custom gadgets can be implemented using the `Gadget` trait. Each gadget is responsible for defining a unqiue *type* (e.g. "Psp22"), intent parsing, and witness verification logic.

The (one-time) [password-gadget](./password.rs) is a minimalistic gadget implementation that allows data to be encrypted under a password. The public NP-statement is "I know the preimage of Sha256(The_Password)". To satisfy the decryption condition, the witness is simply "The_Password". Note that the first corect invocation reveals the password to all fangor workers, so this should be considered as a one-time-password.

The [psp22-gadget](./psp22.rs) is a more complex implementation requiring a psp22 contract to be deployed against a substrate backend. Given a contract address and minimum balance, the gadget statement is: "I know that a given public key has at least the minimum balance of the psp22 token".  It allows data to be encrypted such that knowledge of the public key of anyone owning at least a minimum balance of the token defined in the psp22 contract can decrypt the data. The gadget has a singular responsiblity that makes it brittle: the witness is public.

The [sr25519-gadget](./sr25519.rs) is a Schnorr signature verification gadget. Our implementation is naive (we are aware it is insecure, this was a quick and dirty poc): the gadget expects signatures are made on the latest account nonce only. By composing the psp22 and sr25519 gadgets, we effectively achieve *token-gated-content*, where the statement becomes "I own at least the minimum balance of the psp22 token".

## Intent Parsing

Each gadget registered in the gadget registry must define a unique identity. They also each define custom parsing rules for data. For example, consider a gadget with `id = "Gadget1"` and parsing rules $g_1(x)$. First, a global parser determines the appropriate gadget based on the id. Then, to describe the intent, we compose the gadget identity with the input to the parsing function: `"Gadget1(input_to_gadget_parser)"`. The input is called a **statement**. It can be thought of like a public key in a witness encryption scheme.

Intents can be composed to form more complex conditions. If the gadget registry supports gadgets `Gadget1, Gadget2, Gadget3`, then we can build an intent that composes them to combine them logically using `&&`: `Gadget1(input1) && Gadget2(input2) && Gadget3(input3)`.

### Example

To encrypt under the psp22-gadget, first deploy a psp22 contract (e.g. `5DiTZLwsFHd19DQcQeYrCA67LKXbarXk3HBp9NWEsA43Mpp4`), the construct the intent:

`Psp22(psp22_contract_addr, minimum_balance)`

e.g. `Psp22(5DiTZLwsFHd19DQcQeYrCA67LKXbarXk3HBp9NWEsA43Mpp4, 1)`

``` sh
./target/debug/quickbeam encrypt \
--message-path test.pdf \
--filename test.pdf \
--config-path config.txt \
--keystore-dir tmp/keystore \
--intent "Psp22(5DiTZLwsFHd19DQcQeYrCA67LKXbarXk3HBp9NWEsA43Mpp4, 1)" \
--contract-addr "5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7"
```

Note: `5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7` is the iris contract address.

To decrypt, you just provide any public key of a wallet that owns at least the minimum balance. e.g. `5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY`.

``` sh
./target/debug/quickbeam decrypt \
--filename test.pdf \
--config-path config.txt \
--witness 5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY \
--pt-filename test.pdf \
--contract-addr 5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7
```

## Intent Composition

Intents can be composed to build more complex verifiers. For example, the psp22 gadget only checks if the provided public key owns an asset in the psp22 contract, but does not verify that the caller is the one who owns it. Contrarily, the sr25519 gadget verifies signatures, but offers no context. By combining them, we can enrypt data such that it is only decryptable when the actual owner of some data calls to fetch it. 

Intent composition uses `&&` as a delimiter, e.g. `Intent1(params1) & Intent2(params2) && ... && IntentN(params3)`.
Currently, Fangorn supports `Password`, `Psp22`, and `Sr25519` intent types. So, for example, combining the Psp22 and Sr25519 gadget would look like: 

``` sh
./target/debug/quickbeam encrypt \
--message-path test.pdf \
--filename test2.pdf \
--config-path config.txt \
--keystore-dir tmp/keystore \
--intent "Psp22(5DHHL4pkrLzxcYRbU5kpt82MDaJYjmSjtEUzjnauHUehU7Td, 1) && Sr25519()" \
--contract-addr "5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7"
```

To decrypt, witnesses for each intent (in order) are combined into a comma separated list (todo: should probably use a different delimiter)

For the Psp22 statement ("The account with pubkey X owns at least the minimum amount of the psp22 asset"), we provide the witness 5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK3 (our pubkey).

For the sr25519 statement ("I know the secret key to the public key that produced a valid signature on a message equal to the latest nonce in the substrate chain for the associated account."), first sign the latest nonce (right now, I do this by manually querying system > account using polkadotjs, but could probably be integrated). Then, concatenate the public key with the signature (hex enocded, but drop 0x). For example:

- pubkey: `5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK3`
- signature: `8a18f0ce316bed54261c939fea6c8f07778300876e690b88b15f0eded0efc54666a4d2823292f9f54c99554cd4925b6ef9dfcf1edc4a406cf393b537c7b53788`
- witness: `5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK38e819e577a476bd3bb9cd2c5e5521a499cd4a0e0a896f8ecb091c6579278923d52c3f579c854d5f0ba76b6e0266eb8851d7bbfb7c59c70cb036678714146c48d`

5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK3, 5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK38a18f0ce316bed54261c939fea6c8f07778300876e690b88b15f0eded0efc54666a4d2823292f9f54c99554cd4925b6ef9dfcf1edc4a406cf393b537c7b53788

So the full witness for the statement "I own at least the minimum balance of the psp22" is:

`5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK3,5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK38e819e577a476bd3bb9cd2c5e5521a499cd4a0e0a896f8ecb091c6579278923d52c3f579c854d5f0ba76b6e0266eb8851d7bbfb7c59c70cb036678714146c48d`

> todo: that's pretty redundant, we can probably do better

``` sh
./target/debug/quickbeam decrypt \
--filename test.pdf \
--config-path config.txt \
--witness "5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK3,5Dvu9PudjrdKTFDCARLbSs2PaCqwGuEDzZ6XYiGL2ZQU8wK38e819e577a476bd3bb9cd2c5e5521a499cd4a0e0a896f8ecb091c6579278923d52c3f579c854d5f0ba76b6e0266eb8851d7bbfb7c59c70cb036678714146c48d" \
--pt-filename test.pdf \
--contract-addr "5Ccuf8QBBoqZtUPFTxwixMd9mfHLUmXhRvNfBdEU7uL1ApR7"
```
