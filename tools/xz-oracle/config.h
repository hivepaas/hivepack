/*
 * config.h for building liblzma 5.8.4 into the oracle on 64-bit Linux and
 * macOS, in place of the one XZ Utils' configure or CMake build writes:
 * the decoders and encoders hivepack-xz has (LZMA1, LZMA2, delta, the BCJ
 * filters, and lzip's decoder), the three checks, and no threads,
 * assembly or CPU-specific code. Without HAVE_IMMINTRIN_H and
 * TUKLIB_FAST_UNALIGNED_ACCESS, the LZ decoder copies exactly what it
 * needs (LZMA_LZ_DECODER_CONFIG 1), as the port does.
 */
#define HAVE_STDBOOL_H 1
#define HAVE_STDINT_H 1
#define HAVE_INTTYPES_H 1
#define HAVE_CHECK_CRC32 1
#define HAVE_CHECK_CRC64 1
#define HAVE_CHECK_SHA256 1
#define HAVE_INTERNAL_SHA256 1
#define HAVE_DECODER_LZMA1 1
#define HAVE_DECODER_LZMA2 1
#define HAVE_LZIP_DECODER 1
#define HAVE_ENCODER_LZMA1 1
#define HAVE_ENCODER_LZMA2 1
#define HAVE_DECODER_DELTA 1
#define HAVE_ENCODER_DELTA 1
#define HAVE_DECODER_X86 1
#define HAVE_ENCODER_X86 1
#define HAVE_DECODER_POWERPC 1
#define HAVE_ENCODER_POWERPC 1
#define HAVE_DECODER_IA64 1
#define HAVE_ENCODER_IA64 1
#define HAVE_DECODER_ARM 1
#define HAVE_ENCODER_ARM 1
#define HAVE_DECODER_ARMTHUMB 1
#define HAVE_ENCODER_ARMTHUMB 1
#define HAVE_DECODER_ARM64 1
#define HAVE_ENCODER_ARM64 1
#define HAVE_DECODER_SPARC 1
#define HAVE_ENCODER_SPARC 1
#define HAVE_DECODER_RISCV 1
#define HAVE_ENCODER_RISCV 1
#define HAVE_MF_HC3 1
#define HAVE_MF_HC4 1
#define HAVE_MF_BT2 1
#define HAVE_MF_BT3 1
#define HAVE_MF_BT4 1
#define SIZEOF_SIZE_T 8
#define TUKLIB_SYMBOL_PREFIX lzma_
#define PACKAGE_NAME "XZ Utils"
#define PACKAGE_URL "https://tukaani.org/xz/"
