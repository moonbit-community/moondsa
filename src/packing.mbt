let seed_bytes: Int = SEEDBYTES
let k: Int = dilithium_context.get_params_set().k
let l: Int = dilithium_context.get_params_set().l
let omega: Int = dilithium_context.get_params_set().omega
let polyt1_packedbytes: Int = 320
let polyt0_packedbytes: Int = 416

suberror SignError 

let polyz_packedbytes: Int = match dilithium_context.get_params_set().level {
    SecurityLevel::Dilithium2  => 576
    _ => 640
  }
let polyeta_packedbytes: Int =
  match dilithium_context.get_params_set().level {
    SecurityLevel::Dilithium2 | SecurityLevel::Dilithium5 => 128
    SecurityLevel::Dilithium3 => 96
  }

/// Bit-pack public key pk = (rho, t1).
pub fn pack_pk(rho: Array[Byte], t1: Polyveck) -> Array[Byte] {
  let pk : Array[Byte] = Array::new()
  pk.append(rho)
  for i in 0..<k {
    let t1_packed = t1.vec[i].pack_t1()
    pk.append(t1_packed)
  }
  pk
}

/// Unpack public key pk = (rho, t1).
pub fn unpack_pk(pk: Array[Byte]) -> (Array[Byte], Polyveck) {
  let rho = pk[0:seed_bytes].to_array()
  let t1: Polyveck = Polyveck::default()
  for i in 0..<k {
    let t1_packed = pk[seed_bytes + i * polyt1_packedbytes:seed_bytes + (i + 1) * polyt1_packedbytes].to_array()
    t1.vec[i].unpack_t1(t1_packed)
  }
  (rho, t1)
}

/// Bit-pack secret key sk = (rho, key, tr, s1, s2, t0).
pub fn pack_sk(
  rho: Array[Byte],
  tr: Array[Byte],
  key: Array[Byte],
  t0: Polyveck,
  s1: Polyvecl,
  s2: Polyveck,
) -> Array[Byte]{
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

/// Unpack secret key sk = (rho, key, tr, s1, s2, t0).
pub fn unpack_sk(
  sk: Array[Byte]
) -> (Array[Byte], Array[Byte], Array[Byte], Polyveck, Polyvecl, Polyveck) {
  let mut idx = 0

  let rho = sk[0:seed_bytes].to_array()
  idx += seed_bytes;

  let key = sk[seed_bytes:seed_bytes + seed_bytes].to_array()
  idx += seed_bytes;

  let tr = sk[seed_bytes + seed_bytes:seed_bytes + seed_bytes + seed_bytes].to_array()
  idx += seed_bytes;

  let s1: Polyvecl = Polyvecl::default()
  for i in 0..<l {
    let packed_eta = sk[idx + i * polyeta_packedbytes:idx + (i + 1) * polyeta_packedbytes].to_array()
    s1.vec[i].unpack_eta(packed_eta)
  }
  idx += l * polyeta_packedbytes;

  let s2: Polyveck = Polyveck::default()
  for i in 0..<k {
    let packed_eta = sk[idx + i * polyeta_packedbytes:idx + (i + 1) * polyeta_packedbytes].to_array()
    s2.vec[i].unpack_eta(packed_eta)
  }
  idx += k * polyeta_packedbytes;

  let t0: Polyveck = Polyveck::default()
  for i in 0..<k {
    let packed_t0 = sk[idx + i * polyt0_packedbytes:idx + (i + 1) * polyt0_packedbytes].to_array()
    t0.vec[i].unpack_t0(packed_t0)
  }
  (rho, key, tr, t0, s1, s2)
}

/// Bit-pack signature sig = (c, z, h).
pub fn pack_sig(c: Array[Byte]?, z: Polyvecl, h: Polyveck) -> Array[Byte]{
  let sig : Array[Byte] = Array::new()

  match c {
    Some(challenge) => sig.append(challenge)
    None => ()
  }

  for i in 0..<l {
    let packed_z = z.vec[i].pack_z()
    sig.append(packed_z)
  }

  // Encode H
  sig.append(Array::make(omega + k, 0))

  let mut cnt = 0;
  for i in 0..<k {
    for j in 0..<N {
      if h.vec[i].coeffs[j] != 0 {
        sig.push(j.to_byte());
        cnt += 1;
      }
    }
    sig.push(cnt.to_byte());
  }
  sig 
}

/// Unpack signature sig = (z, h, c).
pub fn unpack_sig(
  sig: Array[Byte]
) -> Result[(Polyvecl, Polyveck, Array[Byte]), SignError] {
  let z = Polyvecl::default()
  let h = Polyveck::default()
  let c = Array::new()
  let mut idx = 0;

  c.append(sig[0:seed_bytes].to_array())
  idx += seed_bytes;

  for i in 0..<l {
    let packed_z = sig[idx + i * polyz_packedbytes:idx + (i + 1) * polyz_packedbytes].to_array()
    z.vec[i].unpack_z(packed_z)
  }
  idx += l * polyz_packedbytes;

  // Decode h
  let mut cnt = 0
  for i in 0..<k {
    if sig[idx + omega + i] < cnt.to_byte() || sig[idx + omega + i] > omega.to_byte() {
      return Err(SignError);
    }
    for j in cnt..<sig[idx + omega + i].to_int() {
      // Coefficients are ordered for strong unforgeability
      if j > cnt && sig[idx + j] <= sig[idx + j - 1] {
        return Err(SignError);
      }
      h.vec[i].coeffs[sig[idx + j].to_int()] = 1;
    }
    cnt = sig[idx + omega + i].to_int();
  }

  // Extra indices are zero for strong unforgeability
  for j in cnt..<omega {
    if sig[idx + j] > 0 {
      return Err(SignError);
    }
  }

  Ok((z, h, c))
}
