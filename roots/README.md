# Roots

`roots` is a command-line interface tool built using **Rust** and the **Fangorn** library it provides utilities for key management and cryptographic signing.

-----

## Features

  * **Key Management:** Generate and inspect SR25519 and ED255129 cryptographic keys stored in a local keystore.
  * **Cryptographic Signing:** Sign arbitrary data (currently a nonce) using a key from the local keystore.

-----

## 🛠️ Usage

The application is structured around several subcommands. Use `--help` on the main command or any subcommand for detailed usage information.

### Installation

1.  Ensure you have **Rust** and **Cargo** installed.
2.  Clone the repository and build the project:

<!-- end list -->

```bash
git clone <repository-url>
cd roots
cargo build --release
# The executable will be available at target/release/roots
```

### Key Management Commands

##### Generate a new keypair
``` sh
./target/debug/roots keygen --keystore-dir <KEYSTORE_DIRECTORY> --vault-pswd <VAULT_PASSWORD> --key-name <KEY_NAME> --key-password <KEY_PASSWORD> --index <INDEX> --print-mnemonic
```
Note: Index is only required when generating Fangorn keys and print-mnemonic is only used for sr25519 keys. Fangorn keys will be overwritten if pointing to the same vault and if they use the same naming scheme used by Fangorn on startup.

#### Inspect keys

``` sh
./target/debug/roots inspect --keystore-dir <KEYSTORE_DIRECTORY> --vault-pswd <VAULT_PASSWORD>  --key-name <KEY_NAME> --key-password <KEY_PASSWORD> --index <INDEX>
```

#### Sign a Message (nonce)

``` sh
./target/debug/roots sign --keystore-dir <KEYSTORE_DIRECTORY> --vault-pswd <VAULT_PASSWORD>  --key-name <KEY_NAME> --key-password <KEY_PASSWORD> --index <INDEX> --nonce <NONCE>
```

#### Verify a Signature (nonce)

``` sh
./target/debug/roots verify --keystore-dir <KEYSTORE_DIRECTORY> --vault-pswd <VAULT_PASSWORD>  --key-name <KEY_NAME> --key-password <KEY_PASSWORD> --signature-hex <SIGNATURE_HEX> --index <INDEX> --nonce <NONCE>
```
