/* Copyright (c) 2025 GMO Cybersecurity by Ierae, Inc. All rights reserved. */

use ::std::arch::x86_64::*;

use crate::rc;

pub type AreionWord = __m128i;

#[inline(always)]
pub unsafe fn load_256(src: &[u8; 32]) -> (AreionWord, AreionWord) {
    (
        _mm_loadu_si128(src[0..16].as_ptr() as *const AreionWord),
        _mm_loadu_si128(src[16..32].as_ptr() as *const AreionWord)
    )    
}

#[inline(always)]
pub unsafe fn store_256(dst: &mut [u8; 32], x0: AreionWord, x1: AreionWord) {
    _mm_storeu_si128(dst[0..16].as_mut_ptr() as *mut AreionWord, x0);
    _mm_storeu_si128(dst[16..32].as_mut_ptr() as *mut AreionWord, x1);
}

#[inline(always)]
pub unsafe fn load_512(src: &[u8; 64]) -> (AreionWord, AreionWord, AreionWord, AreionWord) {
    (
        _mm_loadu_si128(src[0..16].as_ptr() as *const AreionWord),
        _mm_loadu_si128(src[16..32].as_ptr() as *const AreionWord),
        _mm_loadu_si128(src[32..48].as_ptr() as *const AreionWord),
        _mm_loadu_si128(src[48..64].as_ptr() as *const AreionWord)
    )    
}

#[inline(always)]
pub unsafe fn store_512(dst: &mut [u8; 64], x0: AreionWord, x1: AreionWord, x2: AreionWord, x3: AreionWord) {
    _mm_storeu_si128(dst[0..16].as_mut_ptr() as *mut AreionWord, x0);
    _mm_storeu_si128(dst[16..32].as_mut_ptr() as *mut AreionWord, x1);
    _mm_storeu_si128(dst[32..48].as_mut_ptr() as *mut AreionWord, x2);
    _mm_storeu_si128(dst[48..64].as_mut_ptr() as *mut AreionWord, x3);
}

#[inline(always)]
pub unsafe fn xor(x: AreionWord, y: AreionWord) -> AreionWord {
    _mm_xor_si128(x, y)
}

#[inline(always)]
pub unsafe fn extract0(x: AreionWord) -> u64 {
    _mm_extract_epi64::<0>(x) as u64
}

#[inline(always)]
pub unsafe fn extract1(x: AreionWord) -> u64 {
    _mm_extract_epi64::<1>(x) as u64
}

#[inline(always)]
pub unsafe fn round_counstant_0(i: usize) -> AreionWord {
    let a = rc::RC0[4 * i + 0];
    let b = rc::RC0[4 * i + 1];
    let c = rc::RC0[4 * i + 2];
    let d = rc::RC0[4 * i + 3];
    _mm_setr_epi32(d as i32, c as i32, b as i32, a as i32)
}

#[inline(always)]
pub unsafe fn round_counstant_1(_: usize) -> AreionWord {
    _mm_setr_epi32(0, 0, 0, 0)
}

#[inline(always)]
pub unsafe fn round_function_256(x0: AreionWord, x1: AreionWord, round: usize) -> (AreionWord, AreionWord) {
    let rc0 = round_counstant_0(round);
    let rc1 = round_counstant_1(round);
    let y1 = _mm_aesenc_si128(_mm_aesenc_si128(x0, rc0), x1);
    let y0 = _mm_aesenclast_si128(x0, rc1);
    (y0, y1)
}

#[inline(always)]
pub unsafe fn inv_round_function_256(y0: AreionWord, y1: AreionWord, round: usize) -> (AreionWord, AreionWord) {
    let rc0 = round_counstant_0(round);
    let rc1 = round_counstant_1(round);
    let x0 = _mm_aesdeclast_si128(y0, rc1);
    let x1 = _mm_aesenc_si128(_mm_aesenc_si128(x0, rc0), y1);
    (x0, x1)
}

#[inline(always)]
pub unsafe fn round_function_512(x0: AreionWord, x1: AreionWord, x2: AreionWord, x3: AreionWord, round: usize) -> (AreionWord, AreionWord, AreionWord, AreionWord) {
    let rc0 = round_counstant_0(round);
    let rc1 = round_counstant_1(round);
    let y1 = _mm_aesenc_si128(x0, x1);
    let y3 = _mm_aesenc_si128(x2, x3);
    let y0 = _mm_aesenclast_si128(x0, rc1);
    let y2 = _mm_aesenc_si128(_mm_aesenclast_si128(x2, rc0), rc1);
    (y0, y1, y2, y3)
}

#[inline(always)]
pub unsafe fn inv_round_function_512(x0: AreionWord, x1: AreionWord, x2: AreionWord, x3: AreionWord, round: usize) -> (AreionWord, AreionWord, AreionWord, AreionWord) {
    let rc0 = round_counstant_0(round);
    let rc1 = round_counstant_1(round);
    let y0 = _mm_aesdeclast_si128(x0, rc1);
    let y2 = _mm_aesdeclast_si128(_mm_aesimc_si128(x2), rc0);
    let y2 = _mm_aesdeclast_si128(y2, rc1);
    let y1 = _mm_aesenc_si128(y0, x1);
    let y3 = _mm_aesenc_si128(y2, x3);
    (y0, y1, y2, y3)
}
