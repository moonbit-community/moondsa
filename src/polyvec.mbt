///| Polyveck is a vector of polynomials and length is k.
pub struct Polyveck {
  vec : Array[Poly]
} derive(Show)

///| deep clone
pub fn Polyveck::copy(self : Polyveck) -> Polyveck {
  let new_vec = Array::new()
  for poly in self.vec {
    new_vec.push(poly.copy())
  }
  { vec: new_vec }
}

///|
impl Default for Polyveck with default() -> Polyveck {
  let k = dilithium_context.get_params_set().k
  let vec = Array::new()
  for _i in 0..<k {
    vec.push(Poly::new())
  }
  { vec: vec }
}

///|
pub struct Polyvecl {
  vec : Array[Poly]
} derive(Show)

///|
impl Default for Polyvecl with default() -> Polyvecl {
  let l = dilithium_context.get_params_set().l
  let vec = Array::new()
  for _i in 0..<l {
    vec.push(Poly::new())
  }
  { vec: vec }
}

///| Implementation of ExpandA. Generates matrix A with uniformly
/// random coefficients a_{i,j} by performing rejection
/// sampling on the output stream of SHAKE128(rho|j|i)
pub fn Polyvecl::matrix_expand(
  mat : Array[Polyvecl],
  rho : Array[Byte]
) -> Unit {
  let k = dilithium_context.get_params_set().k
  let l = dilithium_context.get_params_set().l
  for i in 0..<k {
    for j in 0..<l {
      mat[i].vec[j].uniform(rho, ((i << 8) + j).to_uint16())
    }
  }
}

///|
pub fn polyvec_matrix_pointwise_montgomery(
  t : Polyveck,
  mat : Array[Polyvecl],
  v : Polyvecl
) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    Polyvecl::pointwise_acc_montgomery(t.vec[i], mat[i], v)
  }
}

///|
pub fn Polyvecl::uniform_eta(
  v : Polyvecl,
  seed : Array[Byte],
  nonce : UInt16
) -> Unit {
  let l = dilithium_context.get_params_set().l
  let mut nonce = nonce
  for i in 0..<l {
    v.vec[i].poly_uniform_eta(seed, nonce)
    nonce += 1
  }
}

///|
pub fn Polyvecl::uniform_gamma1(
  v : Polyvecl,
  seed : Array[Byte],
  nonce : UInt16
) -> Unit {
  let l = dilithium_context.get_params_set().l
  let l_u16 = l.to_uint16()
  for i in 0..<l {
    v.vec[i].uniform_gamma1(seed, l_u16 * nonce + i.to_uint16())
  }
}

///|
pub fn Polyvecl::reduce(v : Polyvecl) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    v.vec[i].reduce()
  }
}

///| Add vectors of polynomials of length L.
/// No modular reduction is performed.
pub fn Polyvecl::add(w : Polyvecl, v : Polyvecl) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    w.vec[i].add(v.vec[i])
  }
}

///| Forward NTT of all polynomials in vector of length L. Output
/// coefficients can be up to 16*Q larger than input coefficients.*
pub fn Polyvecl::ntt(v : Polyvecl) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    v.vec[i].ntt()
  }
}

///|
pub fn Polyvecl::invntt_tomont(v : Polyvecl) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    v.vec[i].inv_ntt_to_mont()
  }
}

///|
pub fn Polyvecl::pointwise_poly_montgomery(
  r : Polyvecl,
  a : Poly,
  v : Polyvecl
) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    r.vec[i].pointwise_montgomery(a, v.vec[i])
  }
}

///| Pointwise multiply vectors of polynomials of length L, multiply
/// resulting vector by 2^{-32} and add (accumulate) polynomials
/// in it. Input/output vectors are in NTT domain representation.
/// Input coefficients are assumed to be less than 22*Q. Output
/// coeffcient are less than 2*L*Q.
pub fn Polyvecl::pointwise_acc_montgomery(
  w : Poly,
  u : Polyvecl,
  v : Polyvecl
) -> Unit {
  let l = dilithium_context.get_params_set().l
  let t = Poly::default()
  w.pointwise_montgomery(u.vec[0], v.vec[0])
  for i in 0..<l {
    t.pointwise_montgomery(u.vec[i], v.vec[i])
    w.add(t)
  }
}

///| Check infinity norm of polynomials in vector of length L.
/// Assumes input coefficients to be standard representatives.
/// Returns 0 if norm of all polynomials is strictly smaller than B and 1
/// otherwise.
pub fn Polyvecl::chknorm(v : Polyvecl, bound : Int) -> Byte {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    if v.vec[i].chknorm(bound) > 0 {
      return 1
    }
  }
  return 0
}

//*********** Vectors of polynomials of length K ****************************

///|
pub fn Polyveck::uniform_eta(
  v : Polyveck,
  seed : Array[Byte],
  nonce : UInt16
) -> Unit {
  let k = dilithium_context.get_params_set().k
  let mut nonce = nonce
  for i in 0..<k {
    v.vec[i].poly_uniform_eta(seed, nonce)
    nonce += 1
  }
}

///| Reduce coefficients of polynomials in vector of length K
/// to representatives in [0,2*Q].
pub fn Polyveck::reduce(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].reduce()
  }
}

///| For all coefficients of polynomials in vector of length K
/// add Q if coefficient is negative.
pub fn Polyveck::caddq(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].caddq()
  }
}

///| Add vectors of polynomials of length K.
/// No modular reduction is performed.
pub fn Polyveck::add(w : Polyveck, v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    w.vec[i].add(v.vec[i])
  }
}

///| Subtract vectors of polynomials of length K.
/// Assumes coefficients of polynomials in second input vector
/// to be less than 2*Q. No modular reduction is performed.
pub fn Polyveck::sub(w : Polyveck, v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    w.vec[i].sub(v.vec[i])
  }
}

///| Multiply vector of polynomials of Length K by 2^D without modular
/// reduction. Assumes input coefficients to be less than 2^{32-D}.
pub fn Polyveck::shiftl(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].shiftl()
  }
}

///| Forward NTT of all polynomials in vector of length K. Output
/// coefficients can be up to 16*Q larger than input coefficients.
pub fn Polyveck::ntt(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].ntt()
  }
}

///| Inverse NTT and multiplication by 2^{32} of polynomials
/// in vector of length K. Input coefficients need to be less
/// than 2*Q.
pub fn Polyveck::invntt_tomont(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].inv_ntt_to_mont()
  }
}

///|
pub fn Polyveck::pointwise_poly_montgomery(
  r : Polyveck,
  a : Poly,
  v : Polyveck
) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    r.vec[i].pointwise_montgomery(a, v.vec[i])
  }
}

///| Check infinity norm of polynomials in vector of length K.
/// Assumes input coefficients to be standard representatives.
/// Returns 0 if norm of all polynomials are strictly smaller than B and 1
/// otherwise.
pub fn Polyveck::chknorm(v : Polyveck, bound : Int) -> Byte {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    if v.vec[i].chknorm(bound) > 0 {
      return 1
    }
  }
  return 0
}

///| For all coefficients a of polynomials in vector of length K,
/// compute a0, a1 such that a mod Q = a1*2^D + a0
/// with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
/// standard representatives.
pub fn Polyveck::power2round(v1 : Polyveck, v0 : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v1.vec[i].power2round(v0.vec[i])
  }
}

///| For all coefficients a of polynomials in vector of length K,
/// compute high and low bits a0, a1 such a mod Q = a1*ALPHA + a0
/// with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
/// set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
/// Assumes coefficients to be standard representatives.
pub fn Polyveck::decompose(v1 : Polyveck, v0 : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v1.vec[i].decompose(v0.vec[i])
  }
}

///| Compute hint vector.
///
/// Returns number of 1 bits.
pub fn Polyveck::make_hint(h : Polyveck, v0 : Polyveck, v1 : Polyveck) -> Int {
  let k = dilithium_context.get_params_set().k
  let mut s = 0
  for i in 0..<k {
    s = s + h.vec[i].make_hint(v0.vec[i], v1.vec[i])
  }
  s
}

///| Use hint vector to correct the high bits of input vector.
pub fn Polyveck::use_hint(w : Polyveck, h : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    w.vec[i].use_hint(h.vec[i])
  }
}

///|
pub fn Polyveck::pack_w1(self : Polyveck) -> Array[Byte] {
  let k = dilithium_context.get_params_set().k
  let r : Array[Byte] = Array::new()
  for i in 0..<k {
    r.append(self.vec[i].pack_w1())
  }
  r
}
