///|
pub const N = 256 // dimension of the polynomial ring Z_q(X^n + 1)

///|
pub const Q = 8380417 // modulus of the polynomial ring Z_q(X^n + 1)

///|
pub const D = 13 // degree of the polynomial

///|
enum SecurityLevel {
  Dilithium2
  Dilithium3
  Dilithium5
}

///|
struct ParameterSet {
  public_key_bytes : Int
  secret_key_bytes : Int
  signature_bytes : Int
  q : Int // Polynomial Ring Z_q(X^n + 1)
  d : Int
  c : Int
  gamma1 : Int // (q - 1) / 16
  gamma2 : Int // gamma1 / 2
  k : Int // s_1 dimension
  l : Int // s_2 (error) dimension
  eta : Int
  beta : Int
  omega : Int
  level : SecurityLevel
}
