///|
pub const N = 256 // dimension of the polynomial ring Z_q(X^n + 1)

///|
pub const Q = 8380417 // modulus of the polynomial ring Z_q(X^n + 1)

///|
pub const D = 13 // degree of the polynomial

///|
pub(all) enum SecurityLevel {
  Dilithium2
  Dilithium3
  Dilithium5
}

///|
pub struct ParameterSet {
  public_key_bytes : Int
  secret_key_bytes : Int
  signature_bytes : Int
  k : Int // s_1 dimension
  l : Int // s_2 (error) dimension
  eta : Int
  tau : Int
  beta : Int
  gamma1 : Int // (q - 1) / 16
  gamma2 : Int // gamma1 / 2
  omega : Int
  level : SecurityLevel
  features : Map[String, String] // features(i.e. "aes" not supported now)
}

///|
fn SecurityLevel::gen_params(
  self : SecurityLevel,
  features~ : Map[String, String] = Map::new()
) -> ParameterSet {
  let public_key_bytes = 1377
  let secret_key_bytes = 1792
  let signature_bytes = 2752
  match self {
    SecurityLevel::Dilithium2 =>
      {
        public_key_bytes,
        secret_key_bytes,
        signature_bytes,
        k: 4,
        l: 4,
        eta: 2,
        tau: 39,
        beta: 78,
        gamma1: 1 << 17,
        gamma2: (Q - 1) / 88,
        omega: 80,
        level: self,
        features,
      }
    SecurityLevel::Dilithium3 =>
      {
        public_key_bytes,
        secret_key_bytes,
        signature_bytes,
        k: 6,
        l: 5,
        eta: 4,
        tau: 49,
        beta: 196,
        gamma1: 1 << 19,
        gamma2: (Q - 1) / 32,
        omega: 55,
        level: self,
        features,
      }
    SecurityLevel::Dilithium5 =>
      {
        public_key_bytes,
        secret_key_bytes,
        signature_bytes,
        k: 8,
        l: 7,
        eta: 2,
        tau: 60,
        beta: 120,
        gamma1: 1 << 19,
        gamma2: (Q - 1) / 32,
        omega: 75,
        level: self,
        features,
      }
  }
}
