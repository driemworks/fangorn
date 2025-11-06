use sp_application_crypto::Ss58Codec;

// "1gsRE7dVeozo4rQHtBEDRmKXz8EpoRYudyikxx4QDn4age4"
pub fn decode_contract_addr(address: &str) -> [u8;32] {
    let mut contract_addr_bytes: [u8; 32] = [0; 32];
    if let Ok(contract_address) =
        sp_core::sr25519::Public::from_ss58check(address)
    {
        contract_addr_bytes = *contract_address.as_array_ref();
    } else {
        panic!("invalid contract address provided: not ss58 format");
    }

    contract_addr_bytes
}
