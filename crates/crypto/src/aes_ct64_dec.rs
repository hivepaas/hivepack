//! AES decryption of four bitsliced blocks: port of `aes_ct64_dec.c`.

use crate::aes_ct64::bitslice_sbox;

/// `br_aes_ct64_bitslice_invSbox`: the inverse S-box, from the forward one.
///
/// The AES S-box is `S(x) = A(I(x)) ^ 0x63`, where `I` is inversion in
/// GF(256) and `A` a linear transform. As inversion is an involution, with
/// `B` the inverse of `A`, `iS(x) = B(S(B(x ^ 0x63)) ^ 0x63)`.
fn bitslice_inv_sbox(q: &mut [u64; 8]) {
    inv_affine(q);
    bitslice_sbox(q);
    inv_affine(q);
}

/// `B(x ^ 0x63)`, on the eight words.
fn inv_affine(q: &mut [u64; 8]) {
    let q0 = !q[0];
    let q1 = !q[1];
    let q2 = q[2];
    let q3 = q[3];
    let q4 = q[4];
    let q5 = !q[5];
    let q6 = !q[6];
    let q7 = q[7];
    q[7] = q1 ^ q4 ^ q6;
    q[6] = q0 ^ q3 ^ q5;
    q[5] = q7 ^ q2 ^ q4;
    q[4] = q6 ^ q1 ^ q3;
    q[3] = q5 ^ q0 ^ q2;
    q[2] = q4 ^ q7 ^ q1;
    q[1] = q3 ^ q6 ^ q0;
    q[0] = q2 ^ q5 ^ q7;
}

fn add_round_key(q: &mut [u64; 8], sk: &[u64; 8]) {
    for (word, key) in q.iter_mut().zip(sk) {
        *word ^= key;
    }
}

fn inv_shift_rows(q: &mut [u64; 8]) {
    for word in q.iter_mut() {
        let x = *word;
        *word = (x & 0x0000_0000_0000_FFFF)
            | ((x & 0x0000_0000_0FFF_0000) << 4)
            | ((x & 0x0000_0000_F000_0000) >> 12)
            | ((x & 0x0000_00FF_0000_0000) << 8)
            | ((x & 0x0000_FF00_0000_0000) >> 8)
            | ((x & 0x000F_0000_0000_0000) << 12)
            | ((x & 0xFFF0_0000_0000_0000) >> 4);
    }
}

fn rotr32(x: u64) -> u64 {
    x.rotate_left(32)
}

fn inv_mix_columns(q: &mut [u64; 8]) {
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let r0 = q0.rotate_right(16);
    let r1 = q1.rotate_right(16);
    let r2 = q2.rotate_right(16);
    let r3 = q3.rotate_right(16);
    let r4 = q4.rotate_right(16);
    let r5 = q5.rotate_right(16);
    let r6 = q6.rotate_right(16);
    let r7 = q7.rotate_right(16);

    q[0] = q5 ^ q6 ^ q7 ^ r0 ^ r5 ^ r7 ^ rotr32(q0 ^ q5 ^ q6 ^ r0 ^ r5);
    q[1] = q0 ^ q5 ^ r0 ^ r1 ^ r5 ^ r6 ^ r7 ^ rotr32(q1 ^ q5 ^ q7 ^ r1 ^ r5 ^ r6);
    q[2] = q0 ^ q1 ^ q6 ^ r1 ^ r2 ^ r6 ^ r7 ^ rotr32(q0 ^ q2 ^ q6 ^ r2 ^ r6 ^ r7);
    q[3] = q0
        ^ q1
        ^ q2
        ^ q5
        ^ q6
        ^ r0
        ^ r2
        ^ r3
        ^ r5
        ^ rotr32(q0 ^ q1 ^ q3 ^ q5 ^ q6 ^ q7 ^ r0 ^ r3 ^ r5 ^ r7);
    q[4] = q1
        ^ q2
        ^ q3
        ^ q5
        ^ r1
        ^ r3
        ^ r4
        ^ r5
        ^ r6
        ^ r7
        ^ rotr32(q1 ^ q2 ^ q4 ^ q5 ^ q7 ^ r1 ^ r4 ^ r5 ^ r6);
    q[5] =
        q2 ^ q3 ^ q4 ^ q6 ^ r2 ^ r4 ^ r5 ^ r6 ^ r7 ^ rotr32(q2 ^ q3 ^ q5 ^ q6 ^ r2 ^ r5 ^ r6 ^ r7);
    q[6] = q3 ^ q4 ^ q5 ^ q7 ^ r3 ^ r5 ^ r6 ^ r7 ^ rotr32(q3 ^ q4 ^ q6 ^ q7 ^ r3 ^ r6 ^ r7);
    q[7] = q4 ^ q5 ^ q6 ^ r4 ^ r6 ^ r7 ^ rotr32(q4 ^ q5 ^ q7 ^ r4 ^ r7);
}

/// `br_aes_ct64_bitslice_decrypt`: the rounds, on blocks already in the
/// bitsliced representation, with the expanded subkeys.
pub(crate) fn bitslice_decrypt(num_rounds: usize, skey: &[u64; 120], q: &mut [u64; 8]) {
    let (round_keys, _) = skey.as_chunks::<8>();
    add_round_key(q, &round_keys[num_rounds]);
    for sk in round_keys[1..num_rounds].iter().rev() {
        inv_shift_rows(q);
        bitslice_inv_sbox(q);
        add_round_key(q, sk);
        inv_mix_columns(q);
    }
    inv_shift_rows(q);
    bitslice_inv_sbox(q);
    add_round_key(q, &round_keys[0]);
}
