///|
/// Polynomial vector operations for the Dilithium signature scheme.
///
/// This module implements operations on vectors of polynomials, which are
/// fundamental data structures in the Dilithium signature scheme. These vectors
/// represent elements in the module lattice used by the underlying cryptographic
/// construction.
///
/// # Mathematical Structure
///
/// The module implements two types of polynomial vectors:
/// - `Polyvecl`: Vectors of length l (typically l = k or l = k+1)
/// - `Polyveck`: Vectors of length k
///
/// Both types operate in the polynomial ring Z_q[X]/(X^N + 1) where:
/// - q = 8380417 (the modulus)
/// - N = 256 (the polynomial degree)
///
/// # Vector Operations
///
/// The module provides essential operations including:
/// - Vector addition and subtraction
/// - Pointwise polynomial multiplication
/// - Norm checking for security bounds
/// - NTT transformations for efficient multiplication
/// - Specialized packing/unpacking for keys and signatures
///
/// # Examples
///
/// ```moonbit
/// // Create polynomial vectors
/// let v1 = @ruifeng/moondsa.Polyveck::default()
/// let v2 = @ruifeng/moondsa.Polyveck::default()
/// 
/// // Vector operations
/// v1.add(v2)  // v1 = v1 + v2
/// let norm = v1.chknorm(1000)  // Check if coefficients are within bounds
/// ```

///|
/// Vector of polynomials with length k, where k is determined by the Dilithium
/// parameter set.
///
/// This structure represents one of the core data types in the Dilithium
/// post-quantum cryptographic scheme. The length k corresponds to the security
/// parameter that defines the dimensions of the underlying lattice problem.
/// Each polynomial in the vector operates in the ring Z\_q\[X]/(X^256 + 1)
/// where q is the modulus used in Dilithium.
///
/// Fields:
///
/// * `vec` : Array containing k polynomials, where each polynomial represents a
///   vector component in the lattice-based operations.
pub struct Polyveck {
  vec : Array[Poly]
} derive(Show)

///|
/// Creates a deep copy of the polynomial vector.
///
/// Parameters:
///
/// * `self` : The polynomial vector to copy.
///
/// Returns a new `Polyveck` instance with deeply copied polynomials, ensuring
/// that modifications to the returned vector or its polynomials do not affect
/// the original.
///
pub fn Polyveck::copy(self : Polyveck) -> Polyveck {
  let new_vec = Array::new()
  for poly in self.vec {
    new_vec.push(poly.copy())
  }
  { vec: new_vec }
}

///|
/// Creates a default `Polyveck` instance with a vector of `k` polynomials,
/// where `k` is determined by the current Dilithium parameter set.
///
/// Returns a new `Polyveck` with each polynomial initialized using
/// `Poly::new()`.
///
/// Example:
///
/// ```moonbit
/// let polyveck = Polyveck::default()
/// println(polyveck.vec.length()) // prints the value of k from current parameter set
/// ```
///
pub impl Default for Polyveck with default() -> Polyveck {
  let k = dilithium_context.get_params_set().k
  let vec = Array::new()
  for _i in 0..<k {
    vec.push(Poly::new())
  }
  { vec, }
}

///|
/// Vector of polynomials of length L.
///
/// `Polyvecl` is a fundamental data structure in the Dilithium post-quantum
/// cryptographic scheme that holds an array of `L` polynomials, where `L` is
/// determined by the current parameter set. This structure is used throughout
/// the algorithm for operations like matrix expansion, pointwise
/// multiplication, and various polynomial transformations in the NTT domain.
pub struct Polyvecl {
  vec : Array[Poly]
} derive(Show)

///|
/// Creates a deep copy of the polynomial vector.
///
/// Parameters:
///
/// * `self` : The polynomial vector to copy.
///
/// Returns a new `Polyvecl` instance that is an independent copy of the
/// original, where each polynomial in the vector is also deeply copied.
///
pub fn Polyvecl::copy(self : Polyvecl) -> Polyvecl {
  let new_vec = Array::new()
  for poly in self.vec {
    new_vec.push(poly.copy())
  }
  { vec: new_vec }
}

///|
/// Creates a default `Polyvecl` instance with polynomials initialized to zero.
///
/// Returns a new `Polyvecl` containing `l` zero-initialized polynomials, where
/// `l` is obtained from the current Dilithium parameter set.
///
pub impl Default for Polyvecl with default() -> Polyvecl {
  let l = dilithium_context.get_params_set().l
  let vec = Array::new()
  for _i in 0..<l {
    vec.push(Poly::new())
  }
  { vec, }
}

///|
/// Implementation of ExpandA. Generates matrix A with uniformly
/// random coefficients a_{i,j} by performing rejection
/// sampling on the output stream of SHAKE128(rho|j|i)
pub fn Polyvecl::matrix_expand(
  mat : Array[Polyvecl],
  rho : Array[Byte],
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
/// Performs matrix-vector multiplication using pointwise Montgomery
/// multiplication in the NTT domain.
///
/// Computes the result of multiplying a matrix of polynomial vectors by a
/// single polynomial vector, where each row of the matrix is multiplied with
/// the input vector and accumulated into the corresponding element of the
/// result vector. This operation is performed in the NTT (Number Theoretic
/// Transform) domain using Montgomery reduction for efficiency.
///
/// Parameters:
///
/// * `t` : The result polynomial vector of length k where the computed products
///   will be stored.
/// * `mat` : A matrix represented as an array of polynomial vectors, where each
///   element is a row of the matrix.
/// * `v` : The input polynomial vector of length l to be multiplied with each
///   row of the matrix.
///
/// Example:
///
/// ```moonbit
/// let t = Polyveck::default()
/// let mat : Array[Polyvecl] = Array::new()
/// let v = Polyvecl::default()
///
/// // Initialize matrix with appropriate dimensions
/// let k = dilithium_context.get_params_set().k
/// for i in 0..<k {
///   mat.push(Polyvecl::default())
/// }
///
/// polyvec_matrix_pointwise_montgomery(t, mat, v)
/// ```
///
pub fn polyvec_matrix_pointwise_montgomery(
  t : Polyveck,
  mat : Array[Polyvecl],
  v : Polyvecl,
) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    Polyvecl::pointwise_acc_montgomery(t.vec[i], mat[i], v)
  }
}

///|
/// Generates uniform random polynomials with coefficients in the range
/// determined by the eta parameter for all polynomials in the vector.
///
/// Parameters:
///
/// * `v` : The polynomial vector of length L to be filled with uniform random
///   polynomials.
/// * `seed` : The random seed bytes used for generating the uniform
///   distribution.
/// * `nonce` : The starting nonce value used to ensure different randomness for
///   each polynomial in the vector.
///
pub fn Polyvecl::uniform_eta(
  v : Polyvecl,
  seed : Array[Byte],
  nonce : UInt16,
) -> Unit {
  let l = dilithium_context.get_params_set().l
  let mut nonce = nonce
  for i in 0..<l {
    v.vec[i].poly_uniform_eta(seed, nonce)
    nonce += 1
  }
}

///|
/// Generates uniform random coefficients for all polynomials in a vector using
/// the gamma1 distribution.
///
/// Parameters:
///
/// * `v` : The polynomial vector of length L to populate with uniform gamma1
///   coefficients.
/// * `seed` : The cryptographic seed used for random number generation.
/// * `nonce` : The base nonce value used to ensure different randomness for
///   each polynomial.
///
/// Panics if the dilithium context is not properly initialized when accessing
/// the parameter set.
///
pub fn Polyvecl::uniform_gamma1(
  v : Polyvecl,
  seed : Array[Byte],
  nonce : UInt16,
) -> Unit {
  let l = dilithium_context.get_params_set().l
  let l_u16 = l.to_uint16()
  for i in 0..<l {
    v.vec[i].uniform_gamma1(seed, l_u16 * nonce + i.to_uint16())
  }
}

///|
/// Reduces the coefficients of all polynomials in the vector to their canonical
/// representatives.
///
/// Parameters:
///
/// * `v` : The polynomial vector of length L whose coefficients will be
///   reduced.
///
/// Example:
///
/// ```moonbit
/// let v : Polyvecl = Polyvecl::default()
/// // ... populate v with polynomial data ...
/// Polyvecl::reduce(v)
/// // All polynomials in v now have reduced coefficients
/// ```
///
pub fn Polyvecl::reduce(v : Polyvecl) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    v.vec[i].reduce()
  }
}

///|
/// Adds two polynomial vectors of length L element-wise without performing
/// modular reduction.
///
/// Parameters:
///
/// * `w` : The first polynomial vector that will store the result of the
///   addition.
/// * `v` : The second polynomial vector to be added to the first vector.
///
/// Panics if the length parameter `l` from the Dilithium context exceeds the
/// actual length of either polynomial vector.
///
/// Example:
///
/// ```moonbit
/// let w = Polyvecl::default()
/// let v = Polyvecl::default()
/// // Assume both vectors have been initialized with some polynomial values
/// w.add(v) // w now contains the element-wise sum of the original w and v
/// ```
///
pub fn Polyvecl::add(w : Polyvecl, v : Polyvecl) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    w.vec[i].add(v.vec[i])
  }
}

///|
/// Applies the forward Number Theoretic Transform (NTT) to all polynomials in
/// the vector of length L.
///
/// Parameters:
///
/// * `v` : The polynomial vector of length L whose polynomials will be
///   transformed in-place.
///
/// Panics if the polynomial vector length does not match the parameter set's L
/// value.
///
/// Example:
///
/// ```moonbit
/// let polyvec = Polyvecl::default()
/// // ... initialize polynomials in polyvec ...
/// polyvec.ntt() // Transform all polynomials to NTT domain
/// ```
///
pub fn Polyvecl::ntt(v : Polyvecl) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    v.vec[i].ntt()
  }
}

///|
/// Applies the inverse Number Theoretic Transform (NTT) to all polynomials in
/// the vector and multiplies the result by the Montgomery constant 2^32.
///
/// Parameters:
///
/// * `v` : The vector of polynomials to transform. Each polynomial in the
///   vector will be modified in-place.
///
/// Panics if the vector length does not match the parameter `l` from the
/// Dilithium context.
///
pub fn Polyvecl::invntt_tomont(v : Polyvecl) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    v.vec[i].inv_ntt_to_mont()
  }
}

///|
/// Multiplies each polynomial in a vector of polynomials by a single polynomial
/// using Montgomery multiplication.
///
/// Parameters:
///
/// * `result` : The output vector of polynomials where the results will be
///   stored.
/// * `polynomial` : The single polynomial to multiply with each polynomial in
///   the input vector.
/// * `input_vector` : The input vector of polynomials to be multiplied.
///
/// Panics if the length of `result` or `input_vector` differs from the
/// parameter `l` in the current Dilithium context.
///
pub fn Polyvecl::pointwise_poly_montgomery(
  r : Polyvecl,
  a : Poly,
  v : Polyvecl,
) -> Unit {
  let l = dilithium_context.get_params_set().l
  for i in 0..<l {
    r.vec[i].pointwise_montgomery(a, v.vec[i])
  }
}

///|
/// Pointwise multiply vectors of polynomials of length L, multiply
/// resulting vector by 2^{-32} and add (accumulate) polynomials
/// in it. Input/output vectors are in NTT domain representation.
/// Input coefficients are assumed to be less than 22*Q. Output
/// coefficient are less than 2*L*Q.
pub fn Polyvecl::pointwise_acc_montgomery(
  w : Poly,
  u : Polyvecl,
  v : Polyvecl,
) -> Unit {
  let l = dilithium_context.get_params_set().l
  let t = Poly::default()
  w.pointwise_montgomery(u.vec[0], v.vec[0])
  for i in 1..<l {
    t.pointwise_montgomery(u.vec[i], v.vec[i])
    w.add(t)
  }
}

///|
/// Check infinity norm of polynomials in vector of length L.
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
/// Generates uniform random polynomials with coefficients in the range \[-eta,
/// eta] for all polynomials in the vector.
///
/// Parameters:
///
/// * `v` : The polynomial vector of length K to be filled with uniform random
///   coefficients.
/// * `seed` : The random seed bytes used for generating the uniform
///   distribution.
/// * `nonce` : The starting nonce value used for randomness generation,
///   incremented for each polynomial.
pub fn Polyveck::uniform_eta(
  v : Polyveck,
  seed : Array[Byte],
  nonce : UInt16,
) -> Unit {
  let k = dilithium_context.get_params_set().k
  let mut nonce = nonce
  for i in 0..<k {
    v.vec[i].poly_uniform_eta(seed, nonce)
    nonce += 1
  }
}

///|
/// Reduces coefficients of all polynomials in the vector to representatives in
/// the range \[0, 2\*Q].
///
/// Parameters:
///
/// * `v` : The polynomial vector of length K whose coefficients will be
///   reduced.
///
/// Panics if the dilithium context is not properly initialized or if the
/// parameter set is invalid.
///
pub fn Polyveck::reduce(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].reduce()
  }
}

///|
/// Converts all negative coefficients in the polynomial vector to their
/// positive equivalent by adding Q (the modulus) to each negative coefficient.
///
/// Parameters:
///
/// * `v` : The polynomial vector of length K whose negative coefficients will
///   be converted to positive form.
///
pub fn Polyveck::caddq(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].caddq()
  }
}

///|
/// Adds two polynomial vectors of length K element-wise without modular
/// reduction.
///
/// Parameters:
///
/// * `w` : The first polynomial vector that will store the result of the
///   addition.
/// * `v` : The second polynomial vector to be added to the first.
///
/// Panics:
///
/// * If either `w` or `v` has fewer than K polynomials, where K is determined
///   by the current Dilithium parameter set.
///
pub fn Polyveck::add(w : Polyveck, v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    w.vec[i].add(v.vec[i])
  }
}

///|
/// Subtract vectors of polynomials of length K.
/// Assumes coefficients of polynomials in second input vector
/// to be less than 2*Q. No modular reduction is performed.
pub fn Polyveck::sub(w : Polyveck, v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    w.vec[i].sub(v.vec[i])
  }
}

///|
/// Multiply vector of polynomials of Length K by 2^D without modular
/// reduction. Assumes input coefficients to be less than 2^{32-D}.
pub fn Polyveck::shiftl(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].shiftl()
  }
}

///|
/// Applies forward Number Theoretic Transform (NTT) to all polynomials in the
/// vector of length K.
///
/// Parameters:
///
/// * `v` : The polynomial vector of length K to transform in-place.
///
/// Panics if the vector length does not match the parameter K from the
/// dilithium context.
///
/// Example:
///
/// ```moonbit
/// let polyvec = Polyveck::default()
/// // ... initialize polynomials in polyvec ...
/// Polyveck::ntt(polyvec)
/// // All polynomials in polyvec are now in NTT domain
/// ```
///
pub fn Polyveck::ntt(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].ntt()
  }
}

///|
/// Applies inverse Number Theoretic Transform (NTT) and multiplies by 2^32 to
/// all polynomials in a vector of length K.
///
/// Parameters:
///
/// * `v` : The polynomial vector of length K to transform. Input coefficients
///   must be less than 2\*Q.
///
/// Panics if the dilithium context is not properly initialized or if the
/// parameter set is invalid.
///
pub fn Polyveck::invntt_tomont(v : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v.vec[i].inv_ntt_to_mont()
  }
}

///|
/// Performs pointwise multiplication of a polynomial with each polynomial in a
/// vector, storing results in the output vector.
///
/// Parameters:
///
/// * `r` : The output vector where results are stored.
/// * `a` : The polynomial to multiply with each element of the input vector.
/// * `v` : The input vector of polynomials.
///
pub fn Polyveck::pointwise_poly_montgomery(
  r : Polyveck,
  a : Poly,
  v : Polyveck,
) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    r.vec[i].pointwise_montgomery(a, v.vec[i])
  }
}

///|
/// Check infinity norm of polynomials in vector of length K.
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

///|
/// For all coefficients a of polynomials in vector of length K,
/// compute a0, a1 such that a mod Q = a1*2^D + a0
/// with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
/// standard representatives.
pub fn Polyveck::power2round(v1 : Polyveck, v0 : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    v1.vec[i].power2round(v0.vec[i])
  }
}

///|
/// For all coefficients a of polynomials in vector of length K,
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

///|
/// Computes hint vectors for polynomial coefficients in each polynomial of the
/// vector.
///
/// Parameters:
///
/// * `h` : The output hint vector where computed hints will be stored.
/// * `v0` : The first input polynomial vector containing low bits from
///   decomposition.
/// * `v1` : The second input polynomial vector containing high bits from
///   decomposition.
///
/// Returns the total number of 1 bits across all hint polynomials in the
/// vector.
///
pub fn Polyveck::make_hint(h : Polyveck, v0 : Polyveck, v1 : Polyveck) -> Int {
  let k = dilithium_context.get_params_set().k
  let mut s = 0
  for i in 0..<k {
    s = s + h.vec[i].make_hint(v0.vec[i], v1.vec[i])
  }
  s
}

///|
/// Uses a hint vector to correct the high bits of the input polynomial vector.
///
/// Parameters:
///
/// * `w` : The polynomial vector whose high bits will be corrected in-place.
/// * `h` : The hint vector containing correction information for each
///   polynomial.
///
/// Example:
///
/// ```moonbit
/// let w = Polyveck::default()
/// let h = Polyveck::default()
/// // ... populate w and h with appropriate values ...
/// w.use_hint(h)
/// // w now has its high bits corrected based on the hint vector h
/// ```
///
pub fn Polyveck::use_hint(w : Polyveck, h : Polyveck) -> Unit {
  let k = dilithium_context.get_params_set().k
  for i in 0..<k {
    w.vec[i].use_hint(h.vec[i])
  }
}

///|
/// Packs the high bits (w1 components) of all polynomials in the vector into a
/// byte array.
///
/// Parameters:
///
/// * `self` : The polynomial vector containing the polynomials whose w1
///   components will be packed.
/// * `r` : The output byte array where the packed w1 data will be stored.
///
/// Panics if the output array `r` is not large enough to hold all packed w1
/// data from the k polynomials in the vector.
///
pub fn Polyveck::pack_w1(self : Polyveck, r : Array[Byte]) -> Unit {
  let k = dilithium_context.get_params_set().k
  let mut idx = 0
  for i in 0..<k {
    let packed_w1 = self.vec[i].pack_w1()
    for j in 0..<packed_w1.length() {
      r[idx + j] = packed_w1[j]
    }
    idx += packed_w1.length()
  }
}
