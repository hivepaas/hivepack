//! AES encryption of four bitsliced blocks: port of `aes_ct64_enc.c`.

use crate::aes_ct64::bitslice_sbox;

fn add_round_key(q: &mut [u64; 8], sk: &[u64; 8]) {
    for (word, key) in q.iter_mut().zip(sk) {
        *word ^= key;
    }
}

fn shift_rows(q: &mut [u64; 8]) {
    for word in q.iter_mut() {
        let x = *word;
        *word = (x & 0x0000_0000_0000_FFFF)
            | ((x & 0x0000_0000_FFF0_0000) >> 4)
            | ((x & 0x0000_0000_000F_0000) << 12)
            | ((x & 0x0000_FF00_0000_0000) >> 8)
            | ((x & 0x0000_00FF_0000_0000) << 8)
            | ((x & 0xF000_0000_0000_0000) >> 12)
            | ((x & 0x0FFF_0000_0000_0000) << 4);
    }
}

fn rotr32(x: u64) -> u64 {
    x.rotate_left(32)
}

fn mix_columns(q: &mut [u64; 8]) {
    let [q0, q1, q2, q3, q4, q5, q6, q7] = *q;
    let r0 = q0.rotate_right(16);
    let r1 = q1.rotate_right(16);
    let r2 = q2.rotate_right(16);
    let r3 = q3.rotate_right(16);
    let r4 = q4.rotate_right(16);
    let r5 = q5.rotate_right(16);
    let r6 = q6.rotate_right(16);
    let r7 = q7.rotate_right(16);

    q[0] = q7 ^ r7 ^ r0 ^ rotr32(q0 ^ r0);
    q[1] = q0 ^ r0 ^ q7 ^ r7 ^ r1 ^ rotr32(q1 ^ r1);
    q[2] = q1 ^ r1 ^ r2 ^ rotr32(q2 ^ r2);
    q[3] = q2 ^ r2 ^ q7 ^ r7 ^ r3 ^ rotr32(q3 ^ r3);
    q[4] = q3 ^ r3 ^ q7 ^ r7 ^ r4 ^ rotr32(q4 ^ r4);
    q[5] = q4 ^ r4 ^ r5 ^ rotr32(q5 ^ r5);
    q[6] = q5 ^ r5 ^ r6 ^ rotr32(q6 ^ r6);
    q[7] = q6 ^ r6 ^ r7 ^ rotr32(q7 ^ r7);
}

/// `br_aes_ct64_bitslice_encrypt`: the rounds, on blocks already in the
/// bitsliced representation, with the expanded subkeys.
pub(crate) fn bitslice_encrypt(num_rounds: usize, skey: &[u64; 120], q: &mut [u64; 8]) {
    let (round_keys, _) = skey.as_chunks::<8>();
    add_round_key(q, &round_keys[0]);
    for sk in &round_keys[1..num_rounds] {
        bitslice_sbox(q);
        shift_rows(q);
        mix_columns(q);
        add_round_key(q, sk);
    }
    bitslice_sbox(q);
    shift_rows(q);
    add_round_key(q, &round_keys[num_rounds]);
}
