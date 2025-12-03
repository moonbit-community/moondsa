///|
/// Generates a cryptographic key pair for the Dilithium post-quantum signature scheme.
///
/// This function implements the key generation algorithm from the NIST FIPS 204 standard.
/// It constructs a Module-LWE (MLWE) key pair where the public key is derived from
/// the secret key through matrix multiplication in the polynomial ring Z_q[X]/(X^N + 1).
///
/// # Algorithm Overview
///
/// The key generation follows the MLWE construction:
/// 1. Generate random seed ρ for matrix expansion and seed κ for secret key derivation
/// 2. Expand ρ into matrix A ∈ R_q^{k×l} using SHAKE128 (deterministic expansion)
/// 3. Sample secret vectors s1 ∈ R_q^l and s2 ∈ R_q^k with coefficients in {-η, ..., η}
/// 4. Compute public vector t = A·s1 + s2 (matrix-vector multiplication)
/// 5. Compress t into t1 (high bits) and t0 (low bits) using power-of-2 rounding
/// 6. Pack (ρ, t1) as public key and (ρ, tr, κ, t0, s1, s2) as secret key
///
/// # Security Construction
///
/// The security relies on the hardness of the Module Learning With Errors problem:
/// - Given (A, t), it's computationally hard to recover (s1, s2)
/// - The error term s2 provides the "learning with errors" hardness
/// - The rounding of t provides compression while maintaining security
///
/// # Parameters
///
/// * `seed` : Either:
///   - `Ok(seed_bytes)`: 32-byte seed for deterministic key generation (ρ = seed)
///   - `Err(rand)`: Random number generator for non-deterministic generation
///
/// # Returns
///
/// A tuple `(public_key, secret_key)` where:
/// - `public_key`: Packed (ρ, t1) - matrix seed + compressed public vector
/// - `secret_key`: Packed (ρ, tr, κ, t0, s1, s2) - complete key material
///
/// # Key Sizes by Security Level
///
/// | Level | Public Key | Secret Key | Security |
/// |-------|------------|------------|----------|
/// | 2     | 1312 bytes | 2528 bytes | 128-bit  |
/// | 3     | 1952 bytes | 4016 bytes | 192-bit  |
/// | 5     | 2592 bytes | 4864 bytes | 256-bit  |
pub fn keypair_gen(
  seed : Result[Array[Byte], Rand],
) -> (Array[Byte], Array[Byte]) {
  let init_seed : Array[Byte] = Array::make(SEEDBYTES, 0)
  let k = dilithium_context.get_params_set().k
  let l = dilithium_context.get_params_set().l
  let publickey_bytes = dilithium_context.get_params_set().publickey_bytes
  match seed {
    Ok(x) => {
      init_seed.clear()
      init_seed.append(x)
    }
    Err(rand) => {
      let x = randombytes(rand, SEEDBYTES)
      init_seed.clear()
      init_seed.append(x)
    }
  }
  let seedbuf : Array[Byte] = Array::make(2 * SEEDBYTES + CRHBYTES, 0)
  let tr : Array[Byte] = Array::make(SEEDBYTES, 0)
  let rho : Array[Byte] = Array::make(SEEDBYTES, 0)
  let rhoprime : Array[Byte] = Array::make(CRHBYTES, 0)
  let key : Array[Byte] = Array::make(SEEDBYTES, 0)
  let mat : Array[Polyvecl] = Array::new()
  let s1 : Polyvecl = Polyvecl::default()
  let s2 : Polyveck = Polyveck::default()
  let t1 : Polyveck = Polyveck::default()
  let t0 : Polyveck = Polyveck::default()
  for i in 0..<k {
    mat.push(Polyvecl::default())
  }

  // Step 1: Derive cryptographic seeds from master seed
  // SHAKE256(seed) → (ρ, ρ', κ) where:
  // - ρ: 32-byte seed for matrix A expansion
  // - ρ': 64-byte seed for secret vector sampling  
  // - κ: 32-byte seed for secret key derivation
  shake256(
    output=seedbuf,
    (2 * SEEDBYTES + CRHBYTES).reinterpret_as_uint(),
    input=init_seed,
    SEEDBYTES.reinterpret_as_uint(),
  )
  rho.clear()
  rho.append(seedbuf[0:SEEDBYTES].to_array())
  rhoprime.clear()
  rhoprime.append(seedbuf[SEEDBYTES:SEEDBYTES + CRHBYTES].to_array())
  key.clear()
  key.append(seedbuf[SEEDBYTES + CRHBYTES:].to_array())

  // Step 2: Construct MLWE instance
  // Expand ρ into matrix A ∈ R_q^{k×l} using SHAKE128
  // Each entry A[i][j] is a polynomial in Z_q[X]/(X^N + 1)
  Polyvecl::matrix_expand(mat, rho)

  // Step 3: Sample secret vectors
  // s1 ∈ R_q^l: coefficients sampled uniformly from {-η, ..., η}
  // s2 ∈ R_q^k: coefficients sampled uniformly from {-η, ..., η}
  // These form the secret key: (s1, s2)
  s1.uniform_eta(rhoprime, 0)
  s2.uniform_eta(rhoprime, l.to_uint16())

  // Step 4: Compute public vector
  // t = A·s1 + s2 ∈ R_q^k
  // This is the MLWE instance: (A, t) where t = A·s1 + s2
  let s1hat = s1.copy()
  s1hat.ntt() // Convert s1 to NTT domain for efficient multiplication
  polyvec_matrix_pointwise_montgomery(t1, mat, s1hat) // t1 = A·s1
  t1.reduce()
  t1.invntt_tomont() // Convert back from NTT domain
  t1.add(s2) // t1 = A·s1 + s2

  // Step 5: Compress public vector
  // Apply power-of-2 rounding: t = t1·2^D + t0
  // t1 contains high bits (public), t0 contains low bits (secret)
  t1.caddq()
  t1.power2round(t0)
  let pk = pack_pk(rho, t1)

  // Step 6: Derive public key commitment
  // tr = H(pk) serves as commitment to public key
  // Used during signing to bind signatures to this specific key
  shake256(
    output=tr,
    SEEDBYTES.reinterpret_as_uint(),
    input=pk,
    publickey_bytes.reinterpret_as_uint(),
  )

  // Step 7: Pack complete key material
  // Public key: (ρ, t1) - matrix seed + compressed public vector
  // Secret key: (ρ, tr, κ, t0, s1, s2) - complete MLWE instance
  let sk = pack_sk(rho, tr, key, t0, s1, s2)
  (pk, sk)
}

///|
/// Creates a digital signature for a message using the Fiat-Shamir with Aborts signature scheme.
///
/// This implements the Dilithium signature algorithm using rejection sampling to ensure
/// signature security. The process follows the "Fiat-Shamir with Aborts" paradigm where
/// the signer repeatedly samples randomness until obtaining a valid signature.
///
/// # Algorithm Overview
///
/// The signing process implements the following steps:
/// 1. Derive deterministic randomness: μ = H(tr || m) where tr = H(pk)
/// 2. Sample masking vector y ∈ R_q^l with coefficients in [-γ1+β, γ1-β]
/// 3. Compute commitment w = A·y (matrix-vector multiplication)
/// 4. Decompose w = w1·2^D + w0 using power-of-2 rounding
/// 5. Compute challenge c = H(μ || w1) (hash-based challenge)
/// 6. Compute response z = y + c·s1
/// 7. Check rejection conditions: ||z||_∞ < γ1-β and ||w0-c·s2||_∞ < γ2-β
/// 8. If rejected, restart with fresh randomness
/// 9. Compute hints h for w1 reconstruction
/// 10. Pack signature as (c, z, h)
///
/// # Security Mechanism
///
/// The rejection sampling ensures:
/// - Signature distributions are independent of secret key
/// - No information leakage through failed attempts
/// - Valid signatures satisfy norm bounds for verification
///
/// # Parameters
///
/// * `message` : Byte array containing the message to be signed
/// * `secret_key` : Packed secret key containing (ρ, tr, κ, t0, s1, s2)
///
/// # Returns
///
/// Byte array containing the signature σ = (c, z, h) where:
/// - c: Challenge polynomial (seed for reconstruction)
/// - z: Response vector with coefficients in [-γ1+β, γ1+β]
/// - h: Hint vector for w1 reconstruction
///
/// # Signature Structure by Security Level
///
/// | Level | Structure | Size |
/// |-------|-----------|------|
/// | 2     | (c, z, h) | 2420 bytes |
/// | 3     | (c, z, h) | 3293 bytes |
/// | 5     | (c, z, h) | 4595 bytes |
///
/// # Rejection Sampling
///
/// The algorithm uses rejection sampling to ensure:
/// - z has small coefficients (prevents key recovery)
/// - w0-c·s2 has small coefficients (prevents forgery)
/// - Expected number of iterations is small (≈ 2.2 for typical parameters)
pub fn sign(m : Array[Byte], sk : Array[Byte]) -> Array[Byte] {
  let k = dilithium_context.get_params_set().k
  let polyw1_packedbytes = dilithium_context.get_params_set().polyw1_packedbytes
  let gamma1 = dilithium_context.get_params_set().gamma1
  let gamma2 = dilithium_context.get_params_set().gamma2
  let beta = dilithium_context.get_params_set().beta
  let omega = dilithium_context.get_params_set().omega
  let sign_bytes = dilithium_context.get_params_set().sign_bytes
  // Step 1: Derive message digest
  // μ = H(tr || m) where tr = H(pk) is the public key commitment
  // This binds the signature to both the message and the public key
  let keymu : Array[Byte] = Array::make(SEEDBYTES + CRHBYTES, 0)
  let mat : Array[Polyvecl] = Array::new()
  let y : Polyvecl = Polyvecl::default()
  let w1 : Polyveck = Polyveck::default()
  let w0 : Polyveck = Polyveck::default()
  let h = Polyveck::default()
  let cp = Poly::default()
  let state = KeccakState::default()
  let rhoprime : Array[Byte] = Array::make(CRHBYTES, 0)
  let (rho, key, tr, t0, s1, s2) = unpack_sk(sk)
  for i in 0..<k {
    mat.push(Polyvecl::default())
  }

  // Construct key || message digest: keymu = key || μ
  for i in 0..<SEEDBYTES {
    keymu[i] = key[i]
  }

  // Compute μ = H(tr || m) - message digest for challenge generation
  shake256_absorb(state, tr, SEEDBYTES.reinterpret_as_uint())
  shake256_absorb(state, m, m.length().reinterpret_as_uint())
  shake256_finalize(state)
  state.pos = keccak_squeeze(
    keymu,
    SEEDBYTES,
    CRHBYTES.reinterpret_as_uint(),
    state.s,
    state.pos,
    SHAKE256_RATE,
  )

  // Step 2: Generate fresh randomness for masking
  // ρ' = H(keymu) - used to sample fresh y for each attempt
  shake256(
    output=rhoprime,
    CRHBYTES.reinterpret_as_uint(),
    input=keymu,
    (SEEDBYTES + CRHBYTES).reinterpret_as_uint(),
  )

  // Step 3: Prepare matrices for efficient computation
  // Expand ρ into matrix A ∈ R_q^{k×l} (same as key generation)
  Polyvecl::matrix_expand(mat, rho)

  // Convert secret vectors to NTT domain for efficient multiplication
  s1.ntt() // s1 in NTT domain
  s2.ntt() // s2 in NTT domain
  t0.ntt() // t0 in NTT domain
  let mut nonce : UInt16 = 0
  let sig : Array[Byte] = Array::make(sign_bytes, 0)

  // Step 4: Fiat-Shamir with Aborts loop
  // Repeat until valid signature is found
  while true {
    // Step 4a: Sample masking vector y ∈ R_q^l
    // y has coefficients uniformly distributed in [-γ1+β, γ1-β]
    y.uniform_gamma1(rhoprime, nonce)
    nonce += 1

    // Step 4b: Compute commitment w = A·y
    // w ∈ R_q^k represents the commitment before challenge
    let z = y.copy()
    z.ntt() // Convert y to NTT domain
    polyvec_matrix_pointwise_montgomery(w1, mat, z) // w1 = A·y
    w1.reduce()
    w1.invntt_tomont() // Convert back from NTT domain

    // Step 4c: Decompose commitment for compression
    // w = w1·2^D + w0 where w1 are high bits, w0 are low bits
    // w1 is used for challenge generation, w0 is discarded
    w1.caddq()
    w1.decompose(w0)
    w1.pack_w1(sig)
    state.init()
    shake256_absorb(
      state,
      keymu[SEEDBYTES:].to_array(),
      CRHBYTES.reinterpret_as_uint(),
    )
    shake256_absorb(state, sig, (k * polyw1_packedbytes).reinterpret_as_uint())
    shake256_finalize(state)
    state.pos = keccak_squeeze(
      sig,
      0,
      SEEDBYTES.reinterpret_as_uint(),
      state.s,
      state.pos,
      SHAKE256_RATE,
    )
    cp.challenge(sig)
    cp.ntt()

    // Compute z, reject if it reveals secret
    Polyvecl::pointwise_poly_montgomery(z, cp, s1)
    z.invntt_tomont()
    z.add(y)
    z.reduce()
    if z.chknorm(gamma1 - beta) > 0 {
      continue
    }

    // Check that subtracting cs2 does not change high bits of w and low bits
    // do not reveal secret information 
    Polyveck::pointwise_poly_montgomery(h, cp, s2)
    h.invntt_tomont()
    w0.sub(h)
    w0.reduce()
    if w0.chknorm(gamma2 - beta) > 0 {
      continue
    }

    // Compute hints for w1
    Polyveck::pointwise_poly_montgomery(h, cp, t0)
    h.invntt_tomont()
    h.reduce()
    if h.chknorm(gamma2) > 0 {
      continue
    }
    w0.add(h)
    let n = Polyveck::make_hint(h, w0, w1)
    if n > omega {
      continue
    }
    // Write signature
    let _ = pack_sig(sig, None, z, h)
    return sig
  }
  panic() // unreachable
}

///|
/// Verifies a Dilithium signature using the Fiat-Shamir verification equation.
///
/// This function implements the verification counterpart to the `sign` function,
/// checking whether a signature σ = (c, z, h) is valid for message m under public key pk = (ρ, t1).
/// It completes the signature lifecycle started by `keypair_gen` and `sign`.
///
/// # Relationship to Key Generation and Signing
///
/// This verification function validates signatures created by the `sign` function using
/// public keys generated by `keypair_gen`. The verification process reconstructs the
/// cryptographic proof that the signer knew the secret key corresponding to the public key.
///
/// # Verification Equation
///
/// The verifier checks the Fiat-Shamir equation: c = H(μ || w1) where:
/// - μ = H(H(ρ, t1) || m) - message digest (same computation as in `sign`)
/// - w1 = HighBits(A·z - c·t1) - reconstructed commitment using signature components
/// - HighBits() extracts high-order bits after rounding (inverse of `sign`'s decomposition)
///
/// # Algorithm Steps
///
/// 1. Parse signature: σ = (c, z, h) and public key: pk = (ρ, t1) (inverse of `pack_sig`)
/// 2. Verify signature format and component bounds (security check)
/// 3. Compute μ = H(H(ρ, t1) || m) - same message digest as used in `sign`
/// 4. Expand ρ into matrix A ∈ R_q^{k×l} using SHAKE128 (same expansion as `keypair_gen`)
/// 5. Reconstruct w1 = HighBits(A·z - c·t1) using hints h (inverse of `sign`'s hint generation)
/// 6. Compute c' = H(μ || w1) - expected challenge (same computation as in `sign`)
/// 7. Verify c = c' - signature validity (final check)
///
/// # Security Properties
///
/// The verification ensures the signature proves knowledge of the secret key without revealing it:
/// - Signature components are within valid ranges (prevents forgery)
/// - Response vector z has bounded coefficients (prevents key recovery)
/// - Reconstructed commitment matches expected value (proves secret key knowledge)
/// - No forgery attempts succeed (maintains unforgeability)
///
/// # Parameters
///
/// * `sig` : Byte array containing signature σ = (c, z, h) from `sign`
/// * `m` : Byte array containing the original message that was signed
/// * `pk` : Byte array containing public key pk = (ρ, t1) from `keypair_gen`
///
/// # Returns
///
/// - `Ok(())`: Signature is valid - verification equation holds, proving the signer knew the secret key
/// - `Err(SignError)`: Signature is invalid - specific failure reason indicating potential forgery or corruption
///
/// # Verification Failures
///
/// Common failure modes indicate security violations:
/// - Invalid signature format (wrong length or encoding) - malformed signature
/// - Response vector z has coefficients outside bounds - potential key recovery attack
/// - Reconstructed commitment doesn't match challenge - signature forgery attempt
/// - Signature components don't satisfy norm constraints - malformed signature
pub fn verify(
  sig : Array[Byte],
  m : Array[Byte],
  pk : Array[Byte],
) -> Result[Unit, SignError] {
  let sign_bytes = dilithium_context.get_params_set().sign_bytes
  let beta = dilithium_context.get_params_set().beta
  let gamma1 = dilithium_context.get_params_set().gamma1
  let k = dilithium_context.get_params_set().k
  let polyw1_packedbytes = dilithium_context.get_params_set().polyw1_packedbytes
  let publickey_bytes = dilithium_context.get_params_set().publickey_bytes
  let buf : Array[Byte] = Array::make(k * polyw1_packedbytes, 0)
  let mu : Array[Byte] = Array::make(CRHBYTES, 0)
  let mut c : Array[Byte] = Array::make(SEEDBYTES, 0)
  let c2 : Array[Byte] = Array::make(SEEDBYTES, 0)
  let cp = Poly::default()
  let mat : Array[Polyvecl] = Array::new()
  let mut z = Polyvecl::default()
  let w1 = Polyveck::default()
  let mut h = Polyveck::default()
  let state = KeccakState::default() // shake256_init()
  if sig.length() != sign_bytes {
    return Err(SignError("Wrong signature length"))
  }
  for i in 0..<k {
    mat.push(Polyvecl::default())
  }
  let (rho, t1) = unpack_pk(pk)
  match unpack_sig(sig) {
    Err(e) => return Err(e)
    Ok((sig_z, sig_h, sig_c)) => {
      c = sig_c
      z = sig_z
      h = sig_h
    }
  }
  if z.chknorm(gamma1 - beta) > 0 {
    return Err(SignError("Invalid signature"))
  }

  // Compute CRH(CRH(rho, t1), msg)
  shake256(
    output=mu,
    SEEDBYTES.reinterpret_as_uint(),
    input=pk,
    publickey_bytes.reinterpret_as_uint(),
  )
  shake256_absorb(state, mu, SEEDBYTES.reinterpret_as_uint())
  shake256_absorb(state, m, m.length().reinterpret_as_uint())
  shake256_finalize(state)
  state.pos = keccak_squeeze(
    mu,
    0,
    CRHBYTES.reinterpret_as_uint(),
    state.s,
    state.pos,
    SHAKE256_RATE,
  )

  // Matrix-vector multiplication; compute Az - c2^dt1
  cp.challenge(c)
  Polyvecl::matrix_expand(mat, rho)
  z.ntt()
  polyvec_matrix_pointwise_montgomery(w1, mat, z)
  cp.ntt()
  t1.shiftl()
  t1.ntt()
  let t1_2 = t1.copy()
  Polyveck::pointwise_poly_montgomery(t1, cp, t1_2)
  w1.sub(t1)
  w1.reduce()
  w1.invntt_tomont()

  // Reconstruct w1
  w1.caddq()
  w1.use_hint(h)
  w1.pack_w1(buf)

  // Call random oracle and verify challenge
  state.init()
  shake256_absorb(state, mu, CRHBYTES.reinterpret_as_uint())
  shake256_absorb(state, buf, (k * polyw1_packedbytes).reinterpret_as_uint())
  shake256_finalize(state)
  state.pos = keccak_squeeze(
    c2,
    0,
    SEEDBYTES.reinterpret_as_uint(),
    state.s,
    state.pos,
    SHAKE256_RATE,
  )
  // Doesn't require constant time equality check
  if c != c2 {
    Err(SignError("verify failed"))
  } else {
    Ok(())
  }
}
