# Intent Gadgets Overview

A  **gadget** is a machine that converts a user *intent* into an *NP-statement* against which users can provide *witnesses* for *verification*. It dicates the rules that Fangorn workers use when verifying witnesses, enabling programmable access control. 

The **gadget registry** allows for the composition of multiple gadgets within a Fangorn node (also: for encryption rules).

## Create a Gadget

The gadget framework is extensible. Custom gadgets can be implemented using the `Gadget` trait.

The [password-gadget](./password.rs) is a minimalistic gadget implementation that allows data to be encrypted under a password. The public NP-statement is "I know the preimage of Sha256(The_Password)". To satisfy the decryption condition, the witness is simply "The_Password". 

The [psp22-gadget](./psp22.rs) is a more complex implementation requiring a [psp22]() contract to be deployed against a substrate backend. Given a contract address and minimum balance, the gadget allows data to be encrypted such that anyone owning at least a minimum balance of the token defined in the psp22 contract can decrypt the data. In other words, it enables *token gated content*. 