///|
type PublicKey Array[Byte]

///|
type SecretKey Array[Byte]

///|
type Message Array[Byte]

///|
pub fn key_gen() -> (PublicKey, SecretKey) {
  ([], [])
}

///|
pub fn sign(sk : SecretKey, m : Array[Byte]) -> Array[Byte] {
  []
}
