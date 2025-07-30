///|
/// Data packing and serialization utilities for Dilithium keys and signatures.
///
/// This module provides functions for serializing and deserializing the various
/// data structures used in the Dilithium signature scheme, including public keys,
/// secret keys, and signatures. The packing formats follow the NIST FIPS 204
/// standard specification.
///
/// # Packing Formats
///
/// The module implements efficient bit-packing techniques to minimize the size
/// of keys and signatures while maintaining security properties. Different
/// polynomial representations use specialized packing schemes optimized for
/// their specific coefficient distributions.
///
/// # Error Handling
///
/// All unpacking operations include comprehensive validation to detect malformed
/// input and prevent security vulnerabilities.
///
/// # Examples
///
/// ```moonbit
/// // Pack public key
/// let pk = @ruifeng/moondsa.pack_pk(rho, t1)
/// 
/// // Pack signature
/// let sig = @ruifeng/moondsa.pack_sig(sig, None, z, h)
/// 
/// // Unpack signature components
/// match @ruifeng/moondsa.unpack_sig(signature) {
///   Ok((z, h, c)) => println("Valid signature format")
///   Err(e) => println("Invalid signature: \(e)")
/// }
/// ```

///|
/// Signature verification or validation error with descriptive message.
///
/// This error type is returned when signature verification fails or when
/// signature/key unpacking encounters invalid data. The error message provides
/// specific information about what validation failed.
suberror SignError String

///|
/// Serializes a public key into its binary representation by concatenating the
/// seed `rho` and packed polynomial vector `t1`.
///
/// Parameters:
///
/// * `rho` : The random seed used in key generation, typically 32 bytes.
/// * `t1` : The polynomial vector representing the public component of the key.
///
/// Returns a byte array containing the packed public key data.
pub fn pack_pk(rho : Array[Byte], t1 : Polyveck) -> Array[Byte] {
  let k = dilithium_context.get_params_set().k
  let pk : Array[Byte] = Array::new()
  pk.append(rho)
  for i in 0..<k {
    let t1_packed = t1.vec[i].pack_t1()
    pk.append(t1_packed)
  }
  pk
}

///|
/// Unpacks a public key from its bit-packed representation into its constituent
/// components.
///
/// Parameters:
///
/// * `pk` : The bit-packed public key as a byte array.
///
/// Returns a tuple containing the seed `rho` and the polynomial vector `t1`.
pub fn unpack_pk(pk : Array[Byte]) -> (Array[Byte], Polyveck) {
  let k = dilithium_context.get_params_set().k
  let rho = pk[0:SEEDBYTES].to_array()
  let t1 : Polyveck = Polyveck::default()
  for i in 0..<k {
    let t1_packed = pk[SEEDBYTES + i * POLYT1_PACKEDBYTES:SEEDBYTES +
    (i + 1) * POLYT1_PACKEDBYTES].to_array()
    t1.vec[i].unpack_t1(t1_packed)
  }
  (rho, t1)
}

///|
/// Serializes a Dilithium secret key into a compact byte array format.
///
/// Parameters:
///
/// * `rho` : A 32-byte seed used for generating the public matrix A.
/// * `tr` : A 64-byte hash of the public key.
/// * `key` : A 32-byte seed used for signing.
/// * `t0` : A polynomial vector containing the low-order bits of t.
/// * `s1` : A polynomial vector containing the first part of the secret key.
/// * `s2` : A polynomial vector containing the second part of the secret key.
///
/// Returns a byte array containing the packed secret key in the format: rho ||
/// key || tr || s1 || s2 || t0.
///
pub fn pack_sk(
  rho : Array[Byte],
  tr : Array[Byte],
  key : Array[Byte],
  t0 : Polyveck,
  s1 : Polyvecl,
  s2 : Polyveck,
) -> Array[Byte] {
  let k = dilithium_context.get_params_set().k
  let l = dilithium_context.get_params_set().l
  let sk : Array[Byte] = Array::new()
  sk.append(rho)
  sk.append(key)
  sk.append(tr)
  for i in 0..<l {
    let packed_eta = s1.vec[i].pack_eta()
    sk.append(packed_eta)
  }
  for i in 0..<k {
    let packed_eta = s2.vec[i].pack_eta()
    sk.append(packed_eta)
  }
  for i in 0..<k {
    let packed_t0 = t0.vec[i].pack_t0()
    sk.append(packed_t0)
  }
  sk
}

///|
/// Unpacks a Dilithium secret key from its binary representation into its
/// constituent components.
///
/// Parameters:
///
/// * `sk` : The packed secret key as a byte array containing the serialized
///   components in the specified order.
///
/// Returns a tuple containing the unpacked secret key components: `(rho, key,
/// tr, t0, s1, s2)` where:
///
/// * `rho` : The random seed used for matrix generation (32 bytes)
/// * `key` : The signing key seed (32 bytes)
/// * `tr` : The hash of the public key (32 bytes)
/// * `t0` : The low-order bits of the NTT of the public key polynomial vector
/// * `s1` : The first secret polynomial vector with coefficients in the range
///   `[-eta, eta]`
/// * `s2` : The second secret polynomial vector with coefficients in the range
///   `[-eta, eta]`
///
pub fn unpack_sk(
  sk : Array[Byte],
) -> (Array[Byte], Array[Byte], Array[Byte], Polyveck, Polyvecl, Polyveck) {
  let k = dilithium_context.get_params_set().k
  let l = dilithium_context.get_params_set().l
  let polyeta_packedbytes = dilithium_context.get_params_set().polyeta_packedbytes
  let mut idx = 0
  let rho = sk[0:SEEDBYTES].to_array()
  idx += SEEDBYTES
  let key = sk[idx:idx + SEEDBYTES].to_array()
  idx += SEEDBYTES
  let tr = sk[idx:idx + SEEDBYTES].to_array()
  idx += SEEDBYTES
  let s1 : Polyvecl = Polyvecl::default()
  for i in 0..<l {
    let packed_eta = sk[idx + i * polyeta_packedbytes:idx +
    (i + 1) * polyeta_packedbytes].to_array()
    s1.vec[i].unpack_eta(packed_eta)
  }
  idx += l * polyeta_packedbytes
  let s2 : Polyveck = Polyveck::default()
  for i in 0..<k {
    let packed_eta = sk[idx + i * polyeta_packedbytes:idx +
    (i + 1) * polyeta_packedbytes].to_array()
    s2.vec[i].unpack_eta(packed_eta)
  }
  idx += k * polyeta_packedbytes
  let t0 : Polyveck = Polyveck::default()
  for i in 0..<k {
    let packed_t0 = sk[idx + i * POLYT0_PACKEDBYTES:idx +
    (i + 1) * POLYT0_PACKEDBYTES].to_array()
    t0.vec[i].unpack_t0(packed_t0)
  }
  (rho, key, tr, t0, s1, s2)
}

///|
/// Bit-packs a Dilithium signature into a byte array format.
///
/// Parameters:
///
/// * `sig` : The output byte array to store the packed signature data.
/// * `c` : The optional challenge hash bytes. If `Some`, the challenge is
///   included in the packed signature; if `None`, the challenge portion is left
///   uninitialized.
/// * `z` : The polynomial vector `z` component of the signature.
/// * `h` : The polynomial vector `h` component of the signature containing hint
///   information.
///
/// Returns the packed signature as a byte array.
///
pub fn pack_sig(
  sig : Array[Byte],
  c : Array[Byte]?,
  z : Polyvecl,
  h : Polyveck,
) -> Array[Byte] {
  let k = dilithium_context.get_params_set().k
  let l = dilithium_context.get_params_set().l
  let omega = dilithium_context.get_params_set().omega
  let polyz_packed_bytes = dilithium_context.get_params_set().polyz_packed_bytes
  let mut idx = 0
  match c {
    Some(challenge) =>
      for i in 0..<SEEDBYTES {
        sig[i] = challenge[i]
      }
    None => ()
  }
  idx += SEEDBYTES
  for i in 0..<l {
    let packed_z = z.vec[i].pack_z()
    for j in idx..<(idx + polyz_packed_bytes) {
      sig[j] = packed_z[j - idx]
    }
    idx += polyz_packed_bytes
  }

  // Encode H
  for i in 0..<(omega + k) {
    sig[idx + i] = 0
  }
  let mut cnt = 0
  for i in 0..<k {
    for j in 0..<N {
      if h.vec[i].coeffs[j] != 0 {
        sig[idx + cnt] = j.to_byte()
        cnt += 1
      }
    }
    sig[idx + omega + i] = cnt.to_byte()
  }
  sig
}

///|
/// Unpacks a Dilithium signature from its byte array representation into its
/// constituent components.
///
/// Parameters:
///
/// * `sig` : The byte array containing the packed signature data.
///
/// Returns a `Result` containing either:
///
/// * `Ok((z, h, c))` where `z` is the polynomial vector of length `l`, `h` is
///   the hint polynomial vector of length `k`, and `c` is the challenge seed
///   array
/// * `Err(SignError)` if the signature format is invalid
///
/// Throws an error of type `SignError` if:
///
/// * The hint polynomial indices are not in ascending order (violates strong
///   unforgeability)
/// * The hint polynomial count exceeds the maximum allowed value `omega`
/// * Extra hint indices contain non-zero values (violates strong
///   unforgeability)
/// * Any other signature format validation fails
pub fn unpack_sig(
  sig : Array[Byte],
) -> Result[(Polyvecl, Polyveck, Array[Byte]), SignError] {
  let k = dilithium_context.get_params_set().k
  let l = dilithium_context.get_params_set().l
  let omega = dilithium_context.get_params_set().omega
  let polyz_packed_bytes = dilithium_context.get_params_set().polyz_packed_bytes
  let z = Polyvecl::default()
  let h = Polyveck::default()
  let c = Array::new()
  let mut idx = 0
  c.append(sig[0:SEEDBYTES].to_array())
  idx += SEEDBYTES
  for i in 0..<l {
    let packed_z = sig[idx + i * polyz_packed_bytes:idx +
    (i + 1) * polyz_packed_bytes].to_array()
    z.vec[i].unpack_z(packed_z)
  }
  idx += l * polyz_packed_bytes

  // Decode h
  let mut cnt = 0
  for i in 0..<k {
    if sig[idx + omega + i] < cnt.to_byte() ||
      sig[idx + omega + i] > omega.to_byte() {
      return Err(SignError("Invalid signature"))
    }
    for j in cnt..<sig[idx + omega + i].to_int() {
      // Coefficients are ordered for strong unforgeability
      if j > cnt && sig[idx + j] <= sig[idx + j - 1] {
        return Err(SignError("Invalid signature"))
      }
      h.vec[i].coeffs[sig[idx + j].to_int()] = 1
    }
    cnt = sig[idx + omega + i].to_int()
  }

  // Extra indices are zero for strong unforgeability
  for j in cnt..<omega {
    if sig[idx + j] > 0 {
      return Err(SignError("Invalid signature"))
    }
  }
  Ok((z, h, c))
}
