///|
pub const N = 256 // dimension of the polynomial ring Z_q(X^n + 1)

///|
pub const Q = 8380417 // modulus of the polynomial ring Z_q(X^n + 1)

///|
pub const D = 13 // degree of the polynomial

///|
pub const SEEDBYTES = 32

///|
pub const CRHBYTES = 64

///| SHAKE128 rate (block size) in bytes | SHAKE128 的比特率（块大小），以字节为单位
pub const SHAKE128_RATE : UInt = 168

///| SHAKE256 rate (block size) in bytes | SHAKE256 的比特率（块大小），以字节为单位
pub const SHAKE256_RATE : UInt = 136

///|
pub const STREAM128_BLOCKBYTES : UInt = SHAKE128_RATE

///|
pub const STREAM256_BLOCKBYTES : UInt = SHAKE256_RATE

///|
pub const POLYT0_PACKEDBYTES : Int = 416

///|
pub const POLYT1_PACKEDBYTES : Int = 320

///|
pub(all) enum SecurityLevel {
  Dilithium2
  Dilithium3
  Dilithium5
}

///|
pub struct ParameterSet {
  k : Int // s_1 dimension
  l : Int // s_2 (error) dimension
  eta : Int
  tau : Int
  beta : Int
  gamma1 : Int // (q - 1) / 16
  gamma2 : Int // gamma1 / 2
  omega : Int
  publickey_bytes : Int
  polyw1_packedbytes : Int
  polyz_packed_bytes : Int
  poly_uniform_gamma1_nblocks : UInt
  polyvech_packed_bytes : Int
  sign_bytes : Int
  level : SecurityLevel
  features : Map[String, String] // features(i.e. "aes" not supported now)
}

///|
fn SecurityLevel::gen_paramset(
  self : SecurityLevel,
  features~ : Map[String, String] = Map::new()
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
        publickey_bytes: SEEDBYTES + 4 * POLYT1_PACKEDBYTES, // seedbytes + k * t1
        polyw1_packedbytes: 192,
        polyz_packed_bytes: 576,
        poly_uniform_gamma1_nblocks: (576 + STREAM256_BLOCKBYTES - 1) /
        STREAM128_BLOCKBYTES, //(polyz_packed_bytes + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
        polyvech_packed_bytes: 80 + 4, // omega + k
        sign_bytes: SEEDBYTES + 4 * 576 + 84, // seedbytes + l * polyz_packed_bytes + polyvech_packed_bytes
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
        polyw1_packedbytes: 128,
        polyz_packed_bytes: 640,
        poly_uniform_gamma1_nblocks: (640 + STREAM256_BLOCKBYTES - 1) /
        STREAM128_BLOCKBYTES, //(polyz_packed_bytes + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
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
        polyw1_packedbytes: 128,
        polyz_packed_bytes: 640,
        poly_uniform_gamma1_nblocks: (640 + STREAM256_BLOCKBYTES - 1) /
        STREAM128_BLOCKBYTES, //(polyz_packed_bytes + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
        polyvech_packed_bytes: 75 + 8, // omega + k
        sign_bytes: SEEDBYTES + 7 * 640 + 83, // seedbytes + l * polyz_packed_bytes + polyvech_packed_bytes
        level: self,
        features,
      }
  }
}
