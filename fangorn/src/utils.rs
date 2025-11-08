use sp_application_crypto::Ss58Codec;
use std::fs;

// "1gsRE7dVeozo4rQHtBEDRmKXz8EpoRYudyikxx4QDn4age4"
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
