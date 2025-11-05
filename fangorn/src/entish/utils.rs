pub fn xor_padded(a: &Vec<u8>, b: &Vec<u8>) -> Vec<u8> {
    let max_len = a.len().max(b.len());
    (0..max_len)
        .map(|i| {
            let x = a.get(i).copied().unwrap_or(0);
            let y = b.get(i).copied().unwrap_or(0);
            x ^ y
        })
        .collect()
}
