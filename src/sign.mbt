///| return (public key, secret key)
pub fn crypto_sign_keypair(
  seed : Result[Array[Byte], Rand]
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

  // Get randomness for rho, rhoprime and key
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

  // Expand matrix
  Polyvecl::matrix_expand(mat, rho)
  // Sample short vectors s1 and s2
  s1.uniform_eta(rhoprime, 0)
  s2.uniform_eta(rhoprime, l.to_uint16())
  // Matrix-vector multiplication
  let s1hat = s1
  s1hat.ntt()
  polyvec_matrix_pointwise_montgomery(t1, mat, s1hat)
  t1.reduce()
  t1.invntt_tomont()
  // Add error vector s2
  t1.add(s2)
  // Extract t1 and write public key
  t1.caddq()
  t1.power2round(t0)
  let pk = pack_pk(rho, t1)

  // Compute H(rho, t1) and write secret key
  shake256(
    output=tr,
    SEEDBYTES.reinterpret_as_uint(),
    input=pk,
    publickey_bytes.reinterpret_as_uint(),
  )
  let sk = pack_sk(rho, tr, key, t0, s1, s2)
  (pk, sk)
}

///| (m, sk) -> sig
pub fn crypto_sign_signature(m : Array[Byte], sk : Array[Byte]) -> Array[Byte] {
  let k = dilithium_context.get_params_set().k
  let polyw1_packedbytes = dilithium_context.get_params_set().polyw1_packedbytes
  let gamma1 = dilithium_context.get_params_set().gamma1
  let gamma2 = dilithium_context.get_params_set().gamma2
  let beta = dilithium_context.get_params_set().beta
  let omega = dilithium_context.get_params_set().omega
  // `key` and `mu` are concatenated
  let keymu : Array[Byte] = Array::make(SEEDBYTES + CRHBYTES, 0)
  let mut nonce : UInt16 = 0
  let mat : Array[Polyvecl] = Array::new()
  let y : Polyvecl = Polyvecl::default()
  let w1 : Polyveck = Polyveck::default()
  let w0 : Polyveck = Polyveck::default()
  let h = Polyveck::default()
  let cp = Poly::default()
  let state = KeccakState::default() //shake256_init()
  let rhoprime : Array[Byte] = Array::make(CRHBYTES, 0)
  let (rho, tr, key, t0, s1, s2) = unpack_sk(sk)
  for i in 0..<k {
    mat.push(Polyvecl::default())
  }

  // set keymu from key
  for i in 0..<SEEDBYTES {
    keymu[i] = key[i]
  }

  // Compute CRH(tr, msg)
  shake256_absorb(state, tr, SEEDBYTES.reinterpret_as_uint())
  shake256_absorb(state, m, m.length().reinterpret_as_uint())
  shake256_finalize(state)
  shake256_squeeze(keymu[SEEDBYTES:], CRHBYTES.reinterpret_as_uint(), state)
  shake256(
    output=rhoprime,
    CRHBYTES.reinterpret_as_uint(),
    input=keymu,
    (SEEDBYTES + CRHBYTES).reinterpret_as_uint(),
  )

  // Expand matrix and transform vectors
  Polyvecl::matrix_expand(mat, rho)
  s1.ntt()
  s2.ntt()
  t0.ntt()
  let mut sig : Array[Byte] = Array::new()
  while true {
    // Sample intermediate vector y
    y.uniform_gamma1(rhoprime, nonce)
    nonce += 1

    // Matrix-vector multiplication
    let z = y
    z.ntt()
    polyvec_matrix_pointwise_montgomery(w1, mat, z)
    w1.reduce()
    w1.invntt_tomont()

    // Decompose w and call the random oracle
    w1.caddq()
    w1.decompose(w0)
    sig = w1.pack_w1()
    state.init()
    shake256_absorb(
      state,
      keymu[SEEDBYTES:].to_array(),
      CRHBYTES.reinterpret_as_uint(),
    )
    shake256_absorb(state, sig, (k * polyw1_packedbytes).reinterpret_as_uint())
    shake256_finalize(state)
    shake256_squeeze(sig, SEEDBYTES.reinterpret_as_uint(), state)
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
    sig = pack_sig(None, z, h)
    break
  }
  sig
}

///|
pub fn crypto_sign_verify(
  sig : Array[Byte],
  m : Array[Byte],
  pk : Array[Byte]
) -> Result[Unit, SignError] {
  let sign_bytes = dilithium_context.get_params_set().sign_bytes
  let beta = dilithium_context.get_params_set().beta
  let gamma1 = dilithium_context.get_params_set().gamma1
  let k = dilithium_context.get_params_set().k
  let polyw1_packedbytes = dilithium_context.get_params_set().polyw1_packedbytes
  let publickey_bytes = dilithium_context.get_params_set().publickey_bytes
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
  shake256_squeeze(mu, CRHBYTES.reinterpret_as_uint(), state)

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
  let buf = w1.pack_w1()
  println("w1: \{w1}")

  // Call random oracle and verify challenge
  state.init()
  shake256_absorb(state, mu, CRHBYTES.reinterpret_as_uint())
  shake256_absorb(state, buf, (k * polyw1_packedbytes).reinterpret_as_uint())
  shake256_finalize(state)
  shake256_squeeze(c2, SEEDBYTES.reinterpret_as_uint(), state)
  // Doesn't require constant time equality check
  println("c :\n\{c}")
  println("c2 :\n\{c2}")
  if c != c2 {
    Err(SignError("verify failed"))
  } else {
    Ok(())
  }
}
