///|
/// Extended random number generation utilities for cryptographic applications.
///
/// This module provides additional random number generation capabilities
/// beyond the standard MoonBit random interface, specifically designed for
/// cryptographic applications requiring high-quality randomness.
///
/// # Security Considerations
///
/// The implementation is designed to support multiple random sources and
/// provides a cryptographically secure random number generator interface
/// suitable for key generation and other security-critical operations.
///
/// # Usage
///
/// This module is primarily used internally by the Dilithium implementation
/// to provide secure random number generation for key generation and
/// non-deterministic signing operations.

///|
/// Type alias for the standard MoonBit random number generator.
typealias @random.Rand

///|
/// Composite random number generator that combines multiple random sources.
///
/// This structure allows combining multiple random number generators to
/// provide enhanced randomness quality and redundancy for cryptographic
/// applications.
struct BigRandom {
  sources : Array[Rand] // Array of underlying random sources
}

///|
fn BigRandom::new(sources : Array[Rand]) -> BigRandom {
  { sources, }
}

///|
impl @random.Source for BigRandom with next(self) -> UInt64 {
  // iteratively get the next random number from the sources
  let mut res = 0UL
  for source in self.sources {
    res = res ^ source.uint64()
  }
  res
}

///| Crate a new BigRandom
/// the length of the seed must be a multiple of 32(256 bits)
pub fn BigRandom::get_random(seed : Array[Byte], level : Int) -> Rand {
  if seed.is_empty() || (level & 31) != 0 || level == 0 {
    panic()
  } else {
    let checksum : Array[Byte] = Array::new(capacity=level)
    checksum.resize(level, 0)
    shake256(
      output=checksum,
      level.reinterpret_as_uint(),
      input=seed,
      seed.length().reinterpret_as_uint(),
    )
    let sources = []
    for i in 0..<(checksum.length() / 32) {
      let bytes = Bytes::from_array(checksum[i * 32:(i + 1) * 32].to_array())
      let random = Rand::chacha8(seed=bytes)
      sources.push(random)
    }
    let sourcePool = BigRandom::new(sources)
    let gen = @random.Rand::new(generator=sourcePool)
    gen
  }
}

///|
pub fn randombytes(rand : Rand, n : Int) -> Array[Byte] {
  let res : Array[Byte] = Array::new(capacity=n)
  for i in 0..<(n / 4) {
    let v = rand.int().to_be_bytes().to_array()
    res.append(v)
  }
  if (n & 3) != 0 {
    let v = rand.int().to_be_bytes().to_array()[:n & 3].to_array()
    res.append(v)
  }
  res
}

///|
test "BigRandom" {
  let seed = "1234567890".to_bytes().to_array()
  let level = 1024
  let rand = BigRandom::get_random(seed, level)
  let mut str = ""
  for i in 0..<100 {
    str += rand.int().to_string()
  }
  println("BigRandom Test: \{str}")
}
