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
  q : Int
  d : Int
  c : Int
  gamma1 : Int // (q - 1) / 16
  gamma2 : Int // gamma1 / 2
  k : Int
  l : Int
  eta : Int
  beta : Int
  omega : Int
  level : SecurityLevel
}
