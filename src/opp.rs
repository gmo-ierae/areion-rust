/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

use std::default;

enum MayBePadded<T> {
    ExactWord(T),
    PaddedWord(T, usize)
}

trait OppWord
where
    Self:Sized,
    Self:std::ops::BitXor<Self, Output = Self>,
    Self:std::ops::BitXorAssign,
    Self:Copy
{
    const BLOCK_SIZE: usize;
    fn zero() -> Self;

    fn from_bytes(bytes: &[u8]) -> MayBePadded<Self>;
    fn into_bytes(bytes: &mut [u8], block: MayBePadded<Self>);
    fn restore_pad(&self, len: usize) -> Self;

    fn permute(&self) -> Self;
    fn inv_permute(&self) -> Self;
    fn phi(&self) -> Self;
    fn init_mask(key: &[u8; 16], nonce: &[u8; 16]) -> Self;

    fn alpha(&self) -> Self {
        self.phi()
    }

    fn beta(&self) -> Self {
        let y = self.phi();
        *self ^ y
    }

    fn gamma(&self) -> Self {
        let y = self.phi();
        let z = y.phi();
        *self ^ y ^ z
    }

    fn mem(&self, mask: Self) -> Self {
        (*self ^ mask).permute() ^ mask
    }

    fn inv_mem(&self, mask: Self) -> Self {
        (*self ^ mask).inv_permute() ^ mask
    }
}

#[derive(Clone, Copy)]
struct OppWord256 {
    a: u64,
    b: u64,
    c: u64,
    d: u64
}

#[derive(Clone, Copy)]
struct OppWord512 {
    s: [u64; 8]
}

fn pad<const N: usize>(bytes: &[u8]) -> [u8; N] {
    std::array::from_fn(|i|
        if i < bytes.len() {
            bytes[i]
        } else if i == bytes.len() {
            0x01
        } else {
            0x00
        }
    )
}

impl OppWord256 {
    fn from_byte_array(bytes: &[u8; 32]) -> OppWord256 {
        let a: &[u8; 8] = bytes[0..8].try_into().unwrap();
        let b: &[u8; 8] = bytes[8..16].try_into().unwrap();
        let c: &[u8; 8] = bytes[16..24].try_into().unwrap();
        let d: &[u8; 8] = bytes[24..32].try_into().unwrap();

        OppWord256 {
            a: u64::from_le_bytes(*a),
            b: u64::from_le_bytes(*b),
            c: u64::from_le_bytes(*c),
            d: u64::from_le_bytes(*d),
        }
    }

    fn into_byte_array(&self) -> [u8; 32] {
        let mut bytes: [u8; 32] = [0; 32];
        bytes[0..8].copy_from_slice(&self.a.to_le_bytes());
        bytes[8..16].copy_from_slice(&self.b.to_le_bytes());
        bytes[16..24].copy_from_slice(&self.c.to_le_bytes());
        bytes[24..32].copy_from_slice(&self.d.to_le_bytes());
        bytes
    }
}

impl OppWord512 {
    fn from_byte_array(bytes: &[u8; 64]) -> OppWord512 {
        OppWord512 {
            s: std::array::from_fn(|i| {
                u64::from_le_bytes(bytes[i * 8 .. i * 8 + 8].try_into().unwrap())
            })
        }
    }

    fn into_byte_array(&self) -> [u8; 64] {
        let mut bytes: [u8; 64] = [0; 64];
        for (i, w) in self.s.into_iter().enumerate() {
            bytes[i * 8 .. i * 8 + 8].copy_from_slice(&w.to_le_bytes());
        }
        bytes
    }
}

impl std::ops::BitXor for OppWord256 {
    type Output = OppWord256;

    fn bitxor(self, rhs: Self) -> Self::Output {
        OppWord256 {
            a: self.a ^ rhs.a,
            b: self.b ^ rhs.b,
            c: self.c ^ rhs.c,
            d: self.d ^ rhs.d
        }
    }
}

impl std::ops::BitXor for OppWord512 {
    type Output = OppWord512;

    fn bitxor(self, rhs: Self) -> Self::Output {
        OppWord512 {
            s: std::array::from_fn(|i| {
                self.s[i] ^ rhs.s[i]
            })
        }
    }
}

impl std::ops::BitXorAssign for OppWord256 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs
    }
}

impl std::ops::BitXorAssign for OppWord512 {
    fn bitxor_assign(&mut self, rhs: Self) {
        *self = *self ^ rhs
    }
}

impl OppWord for OppWord256 {
    const BLOCK_SIZE: usize = 32;

    fn zero() -> Self {
        OppWord256 {
            a: 0, b: 0, c: 0, d: 0
        }
    }
    
    fn from_bytes(bytes: &[u8]) -> MayBePadded<Self> {
        if let Some(bytes) = bytes.first_chunk() {
            MayBePadded::ExactWord(OppWord256::from_byte_array(bytes))
        } else {
            MayBePadded::PaddedWord(OppWord256::from_byte_array(&pad(bytes)), bytes.len())
        }
    }

    fn into_bytes(bytes: &mut [u8], block: MayBePadded<Self>) {
        match block {
            MayBePadded::ExactWord(block) =>
                bytes.copy_from_slice(&block.into_byte_array()),
            MayBePadded::PaddedWord(block, len) =>
                bytes.copy_from_slice(&block.into_byte_array()[0..len]),
        }
    }

    fn restore_pad(&self, len: usize) -> Self {
        Self::from_byte_array(&pad(&self.into_byte_array()[0..len]))
    }

    fn permute(&self) -> Self {
        let buffer = self.into_byte_array();
        let mut buffer_out: [u8; 32] = [0; 32];
        unsafe { crate::permute_areion_256u8_default(&mut buffer_out, &buffer) }
        Self::from_byte_array(&buffer_out)
    }

    fn inv_permute(&self) -> Self {
        let buffer = self.into_byte_array();
        let mut buffer_out: [u8; 32] = [0; 32];
        unsafe { crate::inv_permute_areion_256u8_default(&mut buffer_out, &buffer) }
        Self::from_byte_array(&buffer_out)
    }

    fn phi(&self) -> Self {
        fn rotl(x: u64, n: u32) -> u64 {
            (x << n) | (x >> 64 - n)
        }
        OppWord256 {
            a: self.b,
            b: self.c,
            c: self.d,
            d: rotl(self.a, 3) ^ (self.d >> 5)
        }
    }

    fn init_mask(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let mut buffer: [u8; 32] = [0; 32];
        buffer[0..16].copy_from_slice(nonce);
        buffer[16..32].copy_from_slice(key);
        Self::from_byte_array(&buffer).permute()
    }

}

impl OppWord for OppWord512 {
    const BLOCK_SIZE: usize = 64;

    fn zero() -> Self {
        OppWord512 {
            s: [0; 8]
        }
    }
    
    fn from_bytes(bytes: &[u8]) -> MayBePadded<Self> {
        if let Some(bytes) = bytes.first_chunk() {
            MayBePadded::ExactWord(OppWord512::from_byte_array(bytes))
        } else {
            MayBePadded::PaddedWord(OppWord512::from_byte_array(&pad(bytes)), bytes.len())
        }
    }

    fn into_bytes(bytes: &mut [u8], block: MayBePadded<Self>) {
        match block {
            MayBePadded::ExactWord(block) =>
                bytes.copy_from_slice(&block.into_byte_array()),
            MayBePadded::PaddedWord(block, len) =>
                bytes.copy_from_slice(&block.into_byte_array()[0..len]),
        }
    }

    fn restore_pad(&self, len: usize) -> Self {
        Self::from_byte_array(&pad(&self.into_byte_array()[0..len]))
    }

    fn permute(&self) -> Self {
        let buffer = self.into_byte_array();
        let mut buffer_out: [u8; 64] = [0; 64];
        unsafe { crate::permute_areion_512u8_default(&mut buffer_out, &buffer) }
        Self::from_byte_array(&buffer_out)
    }

    fn inv_permute(&self) -> Self {
        let buffer = self.into_byte_array();
        let mut buffer_out: [u8; 64] = [0; 64];
        unsafe { crate::inv_permute_areion_512u8_default(&mut buffer_out, &buffer) }
        Self::from_byte_array(&buffer_out)
    }

    fn phi(&self) -> Self {
        fn rotl(x: u64, n: u32) -> u64 {
            (x << n) | (x >> 64 - n)
        }
        OppWord512 {
            s: std::array::from_fn(|i| {
                if i == 7 {
                    rotl(self.s[0], 29) ^ (self.s[1] << 9)
                } else {
                    self.s[i + 1]
                }
            })
        }
    }

    fn init_mask(key: &[u8; 16], nonce: &[u8; 16]) -> Self {
        let mut buffer: [u8; 64] = [0; 64];
        buffer[0..16].copy_from_slice(nonce);
        buffer[48..64].copy_from_slice(key);
        Self::from_byte_array(&buffer).permute()
    }
}

struct OppState<Word: OppWord> {
    state: Word,
    mask: Word
}

impl<Word: OppWord> OppState<Word> {
    fn absorb_block(&mut self, input: &[u8]) {
        match Word::from_bytes(input) {
            MayBePadded::ExactWord(in_block) => {
                self.state ^= in_block.mem(self.mask);
                self.mask = self.mask.alpha()
            }
            MayBePadded::PaddedWord(in_block, _len) => {
                let mask = self.mask.beta();
                self.state ^= in_block.mem(mask);
                self.mask = mask.alpha()
            }
        }
    }

    fn encrypt_block(&mut self, output: &mut [u8], input: &[u8]) {
        match Word::from_bytes(input) {
            MayBePadded::ExactWord(in_block) => {
                let out_block = in_block.mem(self.mask);
                Word::into_bytes(output, MayBePadded::ExactWord(out_block));
                self.state ^= in_block;
                self.mask = self.mask.alpha()
            }
            MayBePadded::PaddedWord(in_block, len) => {
                let mask = self.mask.beta();
                let out_block = Word::zero().mem(mask) ^ in_block;
                Word::into_bytes(output, MayBePadded::PaddedWord(out_block, len));
                self.state ^= in_block;
                self.mask = mask
            }
        }
    }

    fn decrypt_block(&mut self, output: &mut [u8], input: &[u8]) {
        match Word::from_bytes(input) {
            MayBePadded::ExactWord(in_block) => {
                let out_block = in_block.inv_mem(self.mask);
                Word::into_bytes(output, MayBePadded::ExactWord(out_block));
                self.state ^= out_block;
                self.mask = self.mask.alpha()
            }
            MayBePadded::PaddedWord(in_block, len) => {
                let mask = self.mask.beta();
                let out_block = Word::zero().mem(mask) ^ in_block;
                let out_block = out_block.restore_pad(len);
                Word::into_bytes(output, MayBePadded::PaddedWord(out_block, len));
                self.state ^= out_block;
                self.mask = mask
            }
        }
    }

    fn absorb(&mut self, input: &[u8]) {
        for in_chunk in input.chunks(Word::BLOCK_SIZE) {
            self.absorb_block(in_chunk)
        }
    }

    fn encrypt(&mut self, output: &mut [u8], input: &[u8]) {
        assert_eq!(input.len(), output.len());
        for (in_chunk, out_chunk) in input.chunks(Word::BLOCK_SIZE).zip(output.chunks_mut(Word::BLOCK_SIZE)) {
            self.encrypt_block(out_chunk, in_chunk)
        }
    }

    fn decrypt(&mut self, output: &mut [u8], input: &[u8]) {
        assert_eq!(input.len(), output.len());
        for (in_chunk, out_chunk) in input.chunks(Word::BLOCK_SIZE).zip(output.chunks_mut(Word::BLOCK_SIZE)) {
            self.decrypt_block(out_chunk, in_chunk)
        }
    }

    fn finalize(absorb_state: Self, encrypt_state: Self) -> [u8; 16] {
        let mask = encrypt_state.mask.beta().beta();
        let block = encrypt_state.state.mem(mask) ^ absorb_state.state;
        let mut buffer: [u8; 16] = [0; 16];
        Word::into_bytes(&mut buffer, MayBePadded::PaddedWord(block, 16));
        buffer
    }
}

fn encrypt_opp<Word: OppWord>(
    ciphertext: &mut [u8], tag: &mut [u8; 16],
    ad: &[u8], plaintext: &[u8], nonce: &[u8; 16], key: &[u8; 16])
{
    let mask = Word::init_mask(key, nonce);
    let mut absorb_state = OppState { state: Word::zero(), mask: mask };
    let mut encrypt_state = OppState { state: Word::zero(), mask: mask.gamma() };

    absorb_state.absorb(ad);
    encrypt_state.encrypt(ciphertext, plaintext);
    *tag = OppState::finalize(absorb_state, encrypt_state)
}

fn decrypt_opp<Word: OppWord>(
    plaintext: &mut [u8], tag: &[u8; 16],
    ad: &[u8], ciphertext: &[u8], nonce: &[u8; 16], key: &[u8; 16]) -> bool
{
    let mask = Word::init_mask(key, nonce);
    let mut absorb_state = OppState { state: Word::zero(), mask: mask };
    let mut encrypt_state = OppState { state: Word::zero(), mask: mask.gamma() };

    absorb_state.absorb(ad);
    encrypt_state.decrypt(plaintext, ciphertext);
    let cipher_tag = OppState::finalize(absorb_state, encrypt_state);
    // TODO: use constant time comparison
    *tag == cipher_tag
}

pub fn encrypt_opp_256(
    ciphertext: &mut [u8], tag: &mut [u8; 16],
    ad: &[u8], plaintext: &[u8], nonce: &[u8; 16], key: &[u8; 16])
{
    encrypt_opp::<OppWord256>(ciphertext, tag, ad, plaintext, nonce, key)
}

pub fn decrypt_opp_256(
    plaintext: &mut [u8], tag: &[u8; 16],
    ad: &[u8], ciphertext: &[u8], nonce: &[u8; 16], key: &[u8; 16]) -> bool
{
    decrypt_opp::<OppWord256>(plaintext, tag, ad, ciphertext, nonce, key)
}

pub fn encrypt_opp_512(
    ciphertext: &mut [u8], tag: &mut [u8; 16],
    ad: &[u8], plaintext: &[u8], nonce: &[u8; 16], key: &[u8; 16])
{
    encrypt_opp::<OppWord512>(ciphertext, tag, ad, plaintext, nonce, key)
}

pub fn decrypt_opp_512(
    plaintext: &mut [u8], tag: &[u8; 16],
    ad: &[u8], ciphertext: &[u8], nonce: &[u8; 16], key: &[u8; 16]) -> bool
{
    decrypt_opp::<OppWord512>(plaintext, tag, ad, ciphertext, nonce, key)
}
