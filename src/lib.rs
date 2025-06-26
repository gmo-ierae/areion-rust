/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

mod rc;
#[cfg(target_arch = "x86_64")]
mod x64;
#[cfg(target_arch = "x86_64")]
use x64 as arch;

#[cfg(target_arch = "aarch64")]
mod aarch64;
#[cfg(target_arch = "aarch64")]
use aarch64 as arch;

use arch::AreionWord;

mod opp;
mod hash;

#[inline(always)]
unsafe fn permute_areion_256_default(x0: AreionWord, x1: AreionWord) -> (AreionWord, AreionWord) {
    let (mut x0, mut x1) = (x0, x1);
    for round in 0..10 {
        (x1, x0) = arch::round_function_256(x0, x1, round)
    }
    (x0, x1)
}

#[inline(always)]
unsafe fn inv_permute_areion_256_default(x0: AreionWord, x1: AreionWord) -> (AreionWord, AreionWord) {
    let (mut x0, mut x1) = (x0, x1);
    for round in 0..10 {
        (x0, x1) = arch::inv_round_function_256(x1, x0, 9 - round)
    }
    (x0, x1)
}

#[inline(always)]
unsafe fn permute_areion_512_default(x0: AreionWord, x1: AreionWord, x2: AreionWord, x3: AreionWord) -> (AreionWord, AreionWord, AreionWord, AreionWord) {
    let (mut x0, mut x1, mut x2, mut x3) = (x0, x1, x2, x3);
    for round in 0..15 {
        (x3, x0, x1, x2) = arch::round_function_512(x0, x1, x2, x3, round)
    }
    (x0, x1, x2, x3)
}

#[inline(always)]
unsafe fn inv_permute_areion_512_default(x0: AreionWord, x1: AreionWord, x2: AreionWord, x3: AreionWord) -> (AreionWord, AreionWord, AreionWord, AreionWord) {
    let (mut x0, mut x1, mut x2, mut x3) = (x0, x1, x2, x3);
    for round in 0..15 {
        (x0, x1, x2, x3) = arch::inv_round_function_512(x3, x0, x1, x2, 14 - round);
    }
    (x0, x1, x2, x3)
}

#[inline(always)]
unsafe fn permute_areion_256u8_default(dst: &mut [u8; 32], src: &[u8; 32]) {
    let (x0, x1) = arch::load_256(src);
    let (x0, x1) = permute_areion_256_default(x0, x1);
    arch::store_256(dst, x0, x1);
}

#[inline(always)]
unsafe fn inv_permute_areion_256u8_default(dst: &mut [u8; 32], src: &[u8; 32]) {
    let (x0, x1) = arch::load_256(src);
    let (x0, x1) = inv_permute_areion_256_default(x0, x1);
    arch::store_256(dst, x0, x1);
}

#[inline(always)]
unsafe fn permute_areion_512u8_default(dst: &mut [u8; 64], src: &[u8; 64]) {
    let (x0, x1, x2, x3) = arch::load_512(src);
    let (x0, x1, x2, x3) = permute_areion_512_default(x0, x1, x2, x3);
    arch::store_512(dst, x0, x1, x2, x3);
}

#[inline(always)]
unsafe fn inv_permute_areion_512u8_default(dst: &mut [u8; 64], src: &[u8; 64]) {
    let (x0, x1, x2, x3) = arch::load_512(src);
    let (x0, x1, x2, x3) = inv_permute_areion_512_default(x0, x1, x2, x3);
    arch::store_512(dst, x0, x1, x2, x3);
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
pub unsafe fn permute_areion_256_x64_aesni(x0: AreionWord, x1: AreionWord) -> (AreionWord, AreionWord) {
    permute_areion_256_default(x0, x1)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
pub unsafe fn inv_permute_areion_256_x64_aesni(x0: AreionWord, x1: AreionWord) -> (AreionWord, AreionWord) {
    inv_permute_areion_256_default(x0, x1)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
pub unsafe fn permute_areion_256u8_x64_aesni(dst: &mut [u8; 32], src: &[u8; 32]) {
    permute_areion_256u8_default(dst, src)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
pub unsafe fn inv_permute_areion_256u8_x64_aesni(dst: &mut [u8; 32], src: &[u8; 32]) {
    inv_permute_areion_256u8_default(dst, src)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
pub unsafe fn permute_areion_512_x64_aesni(x0: AreionWord, x1: AreionWord, x2: AreionWord, x3: AreionWord) -> (AreionWord, AreionWord, AreionWord, AreionWord) {
    permute_areion_512_default(x0, x1, x2, x3)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
pub unsafe fn inv_permute_areion_512_x64_aesni(x0: AreionWord, x1: AreionWord, x2: AreionWord, x3: AreionWord) -> (AreionWord, AreionWord, AreionWord, AreionWord) {
    inv_permute_areion_512_default(x0, x1, x2, x3)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
pub unsafe fn permute_areion_512u8_x64_aesni(dst: &mut [u8; 64], src: &[u8; 64]) {
    permute_areion_512u8_default(dst, src)
}

#[cfg(target_arch = "x86_64")]
#[target_feature(enable = "aes")]
pub unsafe fn inv_permute_areion_512u8_x64_aesni(dst: &mut [u8; 64], src: &[u8; 64]) {
    inv_permute_areion_512u8_default(dst, src)
}

pub use opp::encrypt_opp_256;
pub use opp::decrypt_opp_256;
pub use opp::encrypt_opp_512;
pub use opp::decrypt_opp_512;

pub use hash::areion_hash_dm_256;
pub use hash::areion_hash_dm_512;
pub use hash::areion_hash_md;

#[cfg(test)]
mod tests;
