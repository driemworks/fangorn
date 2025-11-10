use sp_application_crypto::Ss58Codec;
use sp_core::crypto::AccountId32;
use std::fs;

pub fn decode_public_key(address: &str) -> [u8; 32] {
    let mut pk_bytes: [u8; 32] = [0; 32];
    if let Ok(account_id) = AccountId32::from_ss58check(address) {
        pk_bytes = *account_id.as_ref();
    } else {
        panic!("invalid public key provided: not ss58 format or invalid checksum/prefix");
    }

    pk_bytes
}

pub fn decode_contract_addr(address: &str) -> [u8; 32] {
    let mut contract_addr_bytes: [u8; 32] = [0; 32];
    if let Ok(contract_address) = sp_core::sr25519::Public::from_ss58check(address) {
        contract_addr_bytes = *contract_address.as_array_ref();
    } else {
        panic!("invalid contract address provided: not ss58 format");
    }

    contract_addr_bytes
}

/// try to load the mnemomic from the file
/// not secure
pub fn load_mnemonic(keystore_path: &String) -> String {
    // going dumb and simple for now: just read the first file in the dir
    let mut files: Vec<_> = fs::read_dir(keystore_path)
        .unwrap()
        .filter_map(|entry| entry.ok())
        .filter(|entry| entry.path().is_file())
        .collect();

    let seed = fs::read_to_string(files[0].path()).expect("Issue reading keystore");
    let formatted = seed.trim().trim_matches('"');
    formatted.to_string()
}
