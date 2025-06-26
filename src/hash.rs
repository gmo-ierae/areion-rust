/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

pub unsafe fn areion_hash_dm_256(hash: &mut [u8; 32], message: &[u8; 32]) {
    let (input0, input1) = super::arch::load_256(message);
    let (cipher0, cipher1) = super::permute_areion_256_default(input0, input1);
    /* xor message to get DM effect */
    let hash0 = super::arch::xor(cipher0, input0);
    let hash1 = super::arch::xor(cipher1, input1);
    super::arch::store_256(hash, hash0, hash1);
}

pub unsafe fn areion_hash_dm_512(hash: &mut [u8; 32], message: &[u8; 64]) {
    let (input0, input1, input2, input3) = super::arch::load_512(message);
    let (cipher0, cipher1, cipher2, cipher3) = super::permute_areion_512_default(input0, input1, input2, input3);
    /* xor message to get DM effect */
    let hash0 = super::arch::xor(cipher0, input0);
    let hash1 = super::arch::xor(cipher1, input1);
    let hash2 = super::arch::xor(cipher2, input2);
    let hash3 = super::arch::xor(cipher3, input3);
    hash[0..8].copy_from_slice(&super::arch::extract1(hash0).to_le_bytes());
    hash[8..16].copy_from_slice(&super::arch::extract1(hash1).to_le_bytes());
    hash[16..24].copy_from_slice(&super::arch::extract0(hash2).to_le_bytes());
    hash[24..32].copy_from_slice(&super::arch::extract0(hash3).to_le_bytes());
}

const IV: [u8; 32] = [
    0x6a, 0x09, 0xe6, 0x67,
    0xbb, 0x67, 0xae, 0x85,
    0x3c, 0x6e, 0xf3, 0x72,
    0xa5, 0x4f, 0xf5, 0x3a,
    0x51, 0x0e, 0x52, 0x7f,
    0x9b, 0x05, 0x68, 0x8c,
    0x1f, 0x83, 0xd9, 0xab,
    0x5b, 0xe0, 0xcd, 0x19,
];

unsafe fn compress(message: &[u8; 32], output: &mut [u8; 32]) {
    let (input0, input1) = super::arch::load_256(message);
    let (input2, input3) = super::arch::load_256(output);
    let (cipher0, cipher1, cipher2, cipher3) = super::permute_areion_512_default(input0, input1, input2, input3);
    /* xor message to get DM effect */
    let hash0 = super::arch::xor(cipher0, input0);
    let hash1 = super::arch::xor(cipher1, input1);
    let hash2 = super::arch::xor(cipher2, input2);
    let hash3 = super::arch::xor(cipher3, input3);
    output[0..8].copy_from_slice(&super::arch::extract1(hash0).to_le_bytes());
    output[8..16].copy_from_slice(&super::arch::extract1(hash1).to_le_bytes());
    output[16..24].copy_from_slice(&super::arch::extract0(hash2).to_le_bytes());
    output[24..32].copy_from_slice(&super::arch::extract0(hash3).to_le_bytes());
}

pub unsafe fn areion_hash_md(hash: &mut [u8; 32], message: &[u8]) {
    let bits: u32 = (message.len() * 8).try_into().unwrap();
    let mut output: [u8; 32] = IV;

    let iter = message.chunks_exact(32);
    let last_chunk = iter.remainder();
    for chunk in iter {
        compress(chunk.try_into().unwrap(), &mut output);
    }
    let mut mlen = last_chunk.len();
    let mut pad: [u8; 32] = [0; 32];
    pad[0..mlen].copy_from_slice(last_chunk);
    pad[mlen] = 0x80;
    mlen += 1;
    if mlen > 28 {
        // need two blocks
        compress(&pad, &mut output);
        pad = [0; 32];
    }
    pad[28..32].copy_from_slice(&bits.to_be_bytes());
    compress(&pad, &mut output);
    *hash = output
}
