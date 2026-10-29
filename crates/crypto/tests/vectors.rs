//! The published test vectors: AES from FIPS-197 (appendix C) and NIST SP
//! 800-38A (F.1, ECB), SHA-1 from FIPS 180, HMAC-SHA1 from RFC 2202 and
//! PBKDF2-HMAC-SHA1 from RFC 6070. `tests/oracle.rs` compares many more
//! inputs with nettle.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod support;

use hivepack_crypto::{Aes, Hmac, HmacKey, Sha1, pbkdf2_hmac_sha1};
use support::{hex, unhex};

fn encrypt(key: &str, blocks: &str) -> String {
    let aes = Aes::new(&unhex(key)).expect("key length");
    let mut data = unhex(blocks);
    for block in data.as_chunks_mut().0 {
        aes.encrypt_block(block);
    }
    // The same, four blocks at a time.
    let mut again = unhex(blocks);
    let (fours, _) = again.as_chunks_mut();
    for blocks in fours.iter_mut() {
        aes.encrypt4(blocks);
    }
    let whole = 64 * fours.len();
    assert_eq!(data[..whole], again[..whole]);
    hex(&data)
}

#[test]
fn aes_fips_197() {
    let plaintext = "00112233445566778899aabbccddeeff";
    assert_eq!(
        encrypt("000102030405060708090a0b0c0d0e0f", plaintext),
        "69c4e0d86a7b0430d8cdb78070b4c55a"
    );
    assert_eq!(
        encrypt(
            "000102030405060708090a0b0c0d0e0f1011121314151617",
            plaintext
        ),
        "dda97ca4864cdfe06eaf70a0ec0d7191"
    );
    assert_eq!(
        encrypt(
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            plaintext
        ),
        "8ea2b7ca516745bfeafc49904b496089"
    );
}

#[test]
fn aes_sp_800_38a_ecb() {
    let plaintext = "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51\
                     30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710";
    assert_eq!(
        encrypt("2b7e151628aed2a6abf7158809cf4f3c", plaintext),
        "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf\
         43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
    );
    assert_eq!(
        encrypt(
            "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
            plaintext
        ),
        "bd334f1d6e45f25ff712a214571fa5cc974104846d0ad3ad7734ecb3ecee4eef\
         ef7afd2270e2e60adce0ba2face6444e9a4b41ba738d6c72fb16691603c18e0e"
    );
    assert_eq!(
        encrypt(
            "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
            plaintext
        ),
        "f3eed1bdb5d2a03c064b5a7e3db181f8591ccb10d410ed26dc5ba74a31362870\
         b6ed21b99ca6f4f9f153e7b1beafed1d23304b7a39f9f3ff067d8d8f9e24ecc7"
    );
}

#[test]
fn aes_refuses_other_key_lengths() {
    for len in [0, 1, 8, 15, 17, 20, 23, 25, 31, 33, 64] {
        assert!(Aes::new(&vec![0; len]).is_none(), "{len}");
    }
}

fn sha1(data: &[u8]) -> String {
    let mut sha1 = Sha1::new();
    sha1.update(data);
    hex(&sha1.out())
}

#[test]
fn sha1_fips_180() {
    assert_eq!(sha1(b""), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
    assert_eq!(sha1(b"abc"), "a9993e364706816aba3e25717850c26c9cd0d89d");
    assert_eq!(
        sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
    );
    assert_eq!(
        sha1(
            b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
              hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"
        ),
        "a49b2446a02c645bf419f995b67091253a04a259"
    );
    // A million times "a", a thousand at a time.
    let mut sha1 = Sha1::new();
    for _ in 0..1000 {
        sha1.update(&[b'a'; 1000]);
    }
    assert_eq!(hex(&sha1.out()), "34aa973cd4c4daa4f61eeb2bdbad27316534016f");
}

#[test]
fn sha1_goes_on_after_out() {
    let mut sha1 = Sha1::new();
    sha1.update(b"ab");
    assert_eq!(hex(&sha1.out()), self::sha1(b"ab"));
    sha1.update(b"c");
    assert_eq!(hex(&sha1.out()), "a9993e364706816aba3e25717850c26c9cd0d89d");
}

fn hmac(key: &[u8], data: &[u8]) -> String {
    let mut hmac = Hmac::new(&HmacKey::new(key));
    hmac.update(data);
    hex(&hmac.out())
}

#[test]
fn hmac_sha1_rfc_2202() {
    assert_eq!(
        hmac(&[0x0b; 20], b"Hi There"),
        "b617318655057264e28bc0b6fb378c8ef146be00"
    );
    assert_eq!(
        hmac(b"Jefe", b"what do ya want for nothing?"),
        "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
    );
    assert_eq!(
        hmac(&[0xaa; 20], &[0xdd; 50]),
        "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
    );
    let key: Vec<u8> = (1..=25).collect();
    assert_eq!(
        hmac(&key, &[0xcd; 50]),
        "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
    );
    assert_eq!(
        hmac(&[0x0c; 20], b"Test With Truncation"),
        "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
    );
    assert_eq!(
        hmac(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key - Hash Key First"
        ),
        "aa4ae5e15272d00e95705637ce8a3b55ed402112"
    );
    assert_eq!(
        hmac(
            &[0xaa; 80],
            b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
        ),
        "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
    );
}

fn pbkdf2(password: &[u8], salt: &[u8], iterations: u32, length: usize) -> String {
    let mut out = vec![0; length];
    pbkdf2_hmac_sha1(password, salt, iterations, &mut out);
    hex(&out)
}

#[test]
fn pbkdf2_hmac_sha1_rfc_6070() {
    assert_eq!(
        pbkdf2(b"password", b"salt", 1, 20),
        "0c60c80f961f0e71f3a9b524af6012062fe037a6"
    );
    assert_eq!(
        pbkdf2(b"password", b"salt", 2, 20),
        "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"
    );
    assert_eq!(
        pbkdf2(b"password", b"salt", 4096, 20),
        "4b007901b765489abead49d926f721d065a429c1"
    );
    assert_eq!(
        pbkdf2(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            25
        ),
        "3d2eec4fe41c849b80c8d83662c0e44a8b291a964cf2f07038"
    );
    assert_eq!(
        pbkdf2(b"pass\0word", b"sa\0lt", 4096, 16),
        "56fa6aa75548099dcc37d7f03425e0c3"
    );
}

#[test]
#[ignore = "16,777,216 rounds"]
fn pbkdf2_hmac_sha1_rfc_6070_long() {
    assert_eq!(
        pbkdf2(b"password", b"salt", 16_777_216, 20),
        "eefe3d61cd4da4e4e9945b3d6ba2158c2634e984"
    );
}

#[test]
fn pbkdf2_zero_rounds_count_as_one() {
    assert_eq!(
        pbkdf2(b"password", b"salt", 0, 20),
        pbkdf2(b"password", b"salt", 1, 20)
    );
}
