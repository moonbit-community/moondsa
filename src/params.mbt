///|
/// Cryptographic parameters for the Dilithium post-quantum signature scheme.
///
/// This module defines the fundamental constants and parameter sets used in
/// the Dilithium digital signature algorithm. These parameters are derived from
/// the NIST FIPS 204 standard and are critical for the security and correctness
/// of the implementation.
///
/// The Dilithium scheme operates in the polynomial ring Z_q[X]/(X^N + 1) where:
/// - N is the degree of the polynomial ring
/// - Q is the modulus for coefficient arithmetic
/// - D is used for rounding operations
///
/// # Examples
///
/// ```moonbit
/// // Access fundamental parameters
/// let dimension = @ruifeng/moondsa.N  // 256
/// let modulus = @ruifeng/moondsa.Q    // 8380417
/// ```

///|
/// The dimension N of the polynomial ring Z_q[X]/(X^N + 1).
/// This determines the degree of polynomials used in the scheme.
pub const N = 256

///|
/// The modulus q for the polynomial ring Z_q[X]/(X^N + 1).
/// All polynomial coefficients are reduced modulo this prime value.
pub const Q = 8380417

///|
/// The rounding parameter D used in power-of-2 rounding operations.
/// This determines the precision of rounding in various cryptographic operations.
pub const D = 13

///|
/// Size in bytes for random seeds used in key generation and signature operations.
/// This corresponds to 256-bit security strength for the seed material.
pub const SEEDBYTES = 32

///|
/// Size in bytes for collision-resistant hash function outputs.
/// This constant defines the output size for cryptographic hash functions,
/// particularly for operations requiring 512-bit (64-byte) digests in the
/// Dilithium signature scheme.
///
/// This constant specifies the output size in bytes for cryptographic hash
/// functions, particularly for operations that require 64-byte hash outputs. In
/// the context of Dilithium, this is commonly used for collision-resistant hash
/// functions and other cryptographic primitives that produce 512-bit (64-byte)
/// digests.
///
pub const CRHBYTES = 64

///|
/// Rate (block size) in bytes for the SHAKE128 extendable-output function.
/// This determines the input block size for the Keccak sponge construction.
pub const SHAKE128_RATE : UInt = 168

///|
/// Rate (block size) in bytes for the SHAKE256 extendable-output function.
/// This determines the input block size for the Keccak sponge construction.
pub const SHAKE256_RATE : UInt = 136

///|
/// Block size in bytes for SHAKE128-based streaming operations.
/// Alias for SHAKE128_RATE to maintain consistency with the reference implementation.
pub const STREAM128_BLOCKBYTES : UInt = SHAKE128_RATE

///|
/// Block size in bytes for SHAKE256-based streaming operations.
/// Alias for SHAKE256_RATE to maintain consistency with the reference implementation.
pub const STREAM256_BLOCKBYTES : UInt = SHAKE256_RATE

///|
/// Size in bytes for packed polynomial coefficients in the t0 representation.
/// Used for efficient storage and transmission of polynomial data.
pub const POLYT0_PACKEDBYTES : Int = 416

///|
/// Size in bytes for packed polynomial coefficients in the t1 representation.
/// Used for efficient storage and transmission of polynomial data.
pub const POLYT1_PACKEDBYTES : Int = 320

///|
/// Security levels supported by the Dilithium signature scheme.
///
/// Each variant provides different security strengths and performance characteristics:
/// - `Dilithium2`: 128-bit classical security, fastest performance
/// - `Dilithium3`: 192-bit classical security, balanced performance
/// - `Dilithium5`: 256-bit classical security, highest security
pub(all) enum SecurityLevel {
  Dilithium2
  Dilithium3
  Dilithium5
}

///|
/// Configuration parameters for Dilithium digital signature scheme variants.
///
/// Fields:
///
/// * `k` : Dimension of the s\_1 vector.
/// * `l` : Dimension of the s\_2 (error) vector.
/// * `eta` : Coefficient range parameter for secret polynomials.
/// * `tau` : Number of non-zero entries in the challenge polynomial.
/// * `beta` : Maximum coefficient of the commitment randomness.
/// * `gamma1` : Parameter for decomposition, computed as (q - 1) / 16.
/// * `gamma2` : Half of gamma1, used for range checks.
/// * `omega` : Maximum number of 1s in the hint polynomial.
/// * `publickey_bytes` : Size of the public key in bytes (seedbytes + k \* t1).
/// * `polyeta_packedbytes` : Size of a packed eta polynomial in bytes.
/// * `polyw1_packedbytes` : Size of a packed w1 polynomial in bytes.
/// * `polyz_packed_bytes` : Size of a packed z polynomial in bytes.
/// * `poly_uniform_gamma1_nblocks` : Number of SHAKE256 blocks needed for
///   sampling gamma1.
/// * `polyvech_packed_bytes` : Size of a packed hint vector in bytes.
/// * `sign_bytes` : Size of the signature in bytes (seedbytes + l \*
///   polyz\_packed\_bytes + polyvech\_packed\_bytes).
/// * `level` : Security level (Dilithium2, Dilithium3, or Dilithium5).
/// * `features` : Additional features map (e.g., "aes" support, currently not
///   supported).
///
///
pub struct ParameterSet {
  k : Int // s_1 dimension
  l : Int // s_2 (error) dimension
  eta : Int
  tau : Int
  beta : Int
  gamma1 : Int // (q - 1) / 16
  gamma2 : Int // gamma1 / 2
  omega : Int
  publickey_bytes : Int // seedbytes + k * t1
  polyeta_packedbytes : Int
  polyw1_packedbytes : Int
  polyz_packed_bytes : Int
  poly_uniform_gamma1_nblocks : UInt //(polyz_packed_bytes + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
  polyvech_packed_bytes : Int
  sign_bytes : Int // seedbytes + l * polyz_packed_bytes + polyvech_packed_bytes
  level : SecurityLevel
  features : Map[String, String] // features(i.e. "aes" not supported now)
}

///|
/// Generates a complete parameter set configuration for the specified Dilithium
/// security level.
///
/// Parameters:
///
/// * `self` : The Dilithium security level (Dilithium2, Dilithium3, or
///   Dilithium5).
/// * `features` : Optional configuration features map for additional settings
///   (currently unused, defaults to empty map).
///
/// Returns a `ParameterSet` containing all cryptographic parameters,
/// dimensions, and byte sizes needed for the specified Dilithium variant.
fn SecurityLevel::gen_paramset(
  self : SecurityLevel,
  features~ : Map[String, String] = Map::new(),
) -> ParameterSet {
  match self {
    SecurityLevel::Dilithium2 =>
      {
        k: 4,
        l: 4,
        eta: 2,
        tau: 39,
        beta: 78,
        gamma1: 1 << 17,
        gamma2: (Q - 1) / 88,
        omega: 80,
        publickey_bytes: SEEDBYTES + 4 * POLYT1_PACKEDBYTES,
        polyeta_packedbytes: 96,
        polyw1_packedbytes: 192,
        polyz_packed_bytes: 576,
        poly_uniform_gamma1_nblocks: (576 + STREAM256_BLOCKBYTES - 1) /
        STREAM256_BLOCKBYTES,
        polyvech_packed_bytes: 80 + 4, // omega + k
        sign_bytes: SEEDBYTES + 4 * 576 + 84,
        level: self,
        features,
      }
    SecurityLevel::Dilithium3 =>
      {
        k: 6,
        l: 5,
        eta: 4,
        tau: 49,
        beta: 196,
        gamma1: 1 << 19,
        gamma2: (Q - 1) / 32,
        omega: 55,
        publickey_bytes: SEEDBYTES + 6 * POLYT1_PACKEDBYTES, // seedbytes + k * t1
        polyeta_packedbytes: 128,
        polyw1_packedbytes: 128,
        polyz_packed_bytes: 640,
        poly_uniform_gamma1_nblocks: (640 + STREAM256_BLOCKBYTES - 1) /
        STREAM256_BLOCKBYTES, //(polyz_packed_bytes + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
        polyvech_packed_bytes: 55 + 6, // omega + k
        sign_bytes: SEEDBYTES + 5 * 640 + 61, // seedbytes + l * polyz_packed_bytes + polyvech_packed_bytes
        level: self,
        features,
      }
    SecurityLevel::Dilithium5 =>
      {
        k: 8,
        l: 7,
        eta: 2,
        tau: 60,
        beta: 120,
        gamma1: 1 << 19,
        gamma2: (Q - 1) / 32,
        omega: 75,
        publickey_bytes: SEEDBYTES + 8 * POLYT1_PACKEDBYTES, // seedbytes + k * t1
        polyeta_packedbytes: 96,
        polyw1_packedbytes: 128,
        polyz_packed_bytes: 640,
        poly_uniform_gamma1_nblocks: (640 + STREAM256_BLOCKBYTES - 1) /
        STREAM256_BLOCKBYTES, //(polyz_packed_bytes + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
        polyvech_packed_bytes: 75 + 8, // omega + k
        sign_bytes: SEEDBYTES + 7 * 640 + 83, // seedbytes + l * polyz_packed_bytes + polyvech_packed_bytes
        level: self,
        features,
      }
  }
}
