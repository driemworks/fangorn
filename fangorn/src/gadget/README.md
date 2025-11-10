# Intents infrastructure overview

An **intent** is the high level demand that defines what the **witness** must satisfy and how it does so. We implemented a very basic DSL to allow for intent definitions and parsing to be easily extended to introduce new kinds of intents to be defined, along with verifiers and storage backends.

You can think of an intent mapping to both a query or claim (the **statement**) and its answer (the witness). For example, an intent "Password(test)" maps to the statement "I know the preimage of Hash(test)", with the valid witness being the password, "test".

A **statement** is simply an NP-relation, represented as an any length string. Statements are produced by passing a query and answer to a **challenge**, a specialized trait to produce statements. It effectively transforms and intent into a statement, while hiding the witness.

A **verifier** is executed by fangorn workers when producing partial decryptions. Effectively, given a statement $S$ (e.g. "I know the preimage of the hash 0x123...") and a witness (e.g. the password is "test"), then a verifier checks if the witness satisfies the statement. 
