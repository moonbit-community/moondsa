///|
/// Polynomial arithmetic module for the Dilithium signature scheme.
///
/// This module implements polynomial operations in the ring Z_q[X]/(X^N + 1),
/// which forms the mathematical foundation of the Dilithium post-quantum
/// signature scheme. The module provides essential operations including
/// polynomial addition, multiplication, number-theoretic transform (NTT),
/// and various encoding/decoding functions.
///
/// # Mathematical Background
///
/// Polynomials in this module represent elements of the quotient ring
/// Z_q[X]/(X^N + 1), where:
/// - Z_q is the ring of integers modulo q
/// - X^N + 1 is the polynomial modulus
/// - N = 256 is the polynomial degree
/// - q = 8380417 is the prime modulus
///
/// # Examples
///
/// ```moonbit
/// // Create a new polynomial with zero coefficients
/// let poly = @ruifeng/moondsa.Poly::new()
/// 
/// // Create from coefficients
/// let coeffs = Array::make(@ruifeng/moondsa.N, 0)
/// coeffs[0] = 42
/// let poly = { coeffs }
/// ```

///|
/// Precomputed value 2^(D-1) used for efficient power-of-2 rounding operations.
/// This constant is derived from the rounding parameter D and is used in
/// various polynomial operations to avoid repeated computation.
const D_SHL : Int = 1 << (D - 1)

///|
/// Polynomial structure containing an array of coefficients for cryptographic
/// operations.
///
/// This structure represents a polynomial in the ring Z\_q\[X]/(X^N + 1) used
/// in lattice-based cryptography, specifically in the Dilithium digital
/// signature scheme. The polynomial has exactly N coefficients, where N is a
/// compile-time constant representing the degree of the polynomial ring.
///
/// Fields:
///
/// * `coeffs` : Array of N integer coefficients representing the polynomial
///   terms from degree 0 to N-1.
///
/// Example:
///
/// ```moonbit
/// let p = @ruifeng/moondsa.Poly::new()
/// p.coeffs[0] = 42  // Set constant term
/// p.coeffs[1] = -17 // Set coefficient of x^1
/// inspect(p.coeffs[0], content="42")
/// inspect(p.coeffs[1], content="-17")
/// ```
///
pub struct Poly {
  coeffs : Array[Int] // Coefficient array / 系数数组
} derive(Show)

///|
/// Default implementation for Poly - creates a polynomial with all zero coefficients.
/// Poly 的默认实现 - 创建所有系数为零的多项式。
impl Default for Poly with default() -> Poly {
  { coeffs: Array::make(N, 0) }
}

///|
/// Creates a new polynomial with all coefficients initialized to zero.
///
/// Returns a new `Poly` instance with all coefficients set to zero.
pub fn Poly::new() -> Poly {
  Poly::default()
}

///|
/// Creates a copy of the polynomial with independent coefficient storage.
///
/// Parameters:
///
/// * `self` : The polynomial to copy.
///
/// Returns a new polynomial with the same coefficients as the original, but
/// with independent storage that can be modified without affecting the original
/// polynomial.
///
/// Example:
///
/// ```moonbit
/// let poly1 = Poly::new()
/// poly1.coeffs[0] = 42
/// let poly2 = poly1.copy()
/// poly2.coeffs[0] = 100
/// // poly1.coeffs[0] is still 42, poly2.coeffs[0] is 100
/// ```
///
pub fn Poly::copy(self : Poly) -> Poly {
  { coeffs: self.coeffs.copy() }
}

///|
/// Add polynomials. No modular reduction is performed.
/// 多项式加法。不执行模约简。
/// 
/// Arguments / 参数: 
/// - self: target polynomial (modified in place) / 目标多项式（原地修改）
/// - other: polynomial to add / 要相加的多项式
pub fn Poly::add(self : Poly, other : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] += other.coeffs[i]
  }
}

///|
/// Performs in-place modular reduction of all polynomial coefficients to their
/// canonical representatives in the range \[0, 2\*Q].
///
/// Parameters:
///
/// * `self` : The polynomial whose coefficients will be reduced in-place.
///
/// Example:
///
/// ```moonbit
/// let poly = Poly::new()
/// // ... populate polynomial with coefficients ...
/// poly.reduce() // All coefficients are now in range [0, 2*Q]
/// ```
///
pub fn Poly::reduce(self : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = reduce32(self.coeffs[i])
  }
}

///|
/// Conditionally adds the modulus `Q` to each coefficient of the polynomial if
/// the coefficient is negative, ensuring all coefficients are in the range \[0,
/// 2\*Q).
///
/// Parameters:
///
/// * `self` : The polynomial whose coefficients will be conditionally adjusted
///   in place.
///
/// Example:
///
/// ```moonbit
/// let poly = Poly::new()
/// // Assume some coefficients are negative after operations
/// poly.caddq() // All negative coefficients now have Q added to them
/// ```
///
pub fn Poly::caddq(self : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = caddq(self.coeffs[i])
  }
}

///|
/// Subtract polynomials. Assumes coefficients of second input
/// polynomial to be less than 2*Q. No modular reduction is
/// performed.
/// 多项式减法。假设第二个输入多项式的系数小于 2*Q。
/// 不执行模约简。
/// 
/// Arguments / 参数: 
/// - self: target polynomial (modified in place) / 目标多项式（原地修改）
/// - other: polynomial to subtract / 要减去的多项式
pub fn Poly::sub(self : Poly, other : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] -= other.coeffs[i]
  }
}

///|
/// Multiply polynomial by 2^D without modular reduction. Assumes
/// input coefficients to be less than 2^{32-D}.
/// 将多项式乘以 2^D，不执行模约简。假设输入系数小于 2^{32-D}。
pub fn Poly::shiftl(self : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = self.coeffs[i] << D
  }
}

///|
/// Performs an in-place forward Number Theoretic Transform (NTT) on the
/// polynomial coefficients.
///
/// Parameters:
///
/// * `self` : The polynomial whose coefficients will be transformed in place.
///
/// Example:
///
/// ```moonbit
/// let poly = Poly::new()
/// // ... initialize polynomial coefficients ...
/// poly.ntt() // Transform coefficients to NTT domain
/// ```
///
pub fn Poly::ntt(self : Poly) -> Unit {
  ntt(self.coeffs)
}

///|
/// Inplace inverse NTT and multiplication by 2^{32}.
/// Input coefficients need to be less than 2*Q.
/// Output coefficients are less than 2*Q.
/// 原地逆向 NTT 并乘以 2^{32}。
/// 输入系数需要小于 2*Q。
/// 输出系数小于 2*Q。
pub fn Poly::inv_ntt_to_mont(self : Poly) -> Unit {
  inv_ntt_to_mont(self.coeffs)
}

///|
/// Pointwise multiplication of polynomials in NTT domain
/// representation and multiplication of resulting polynomial
/// by 2^{-32}. Output coefficients are less than 2*Q if input
/// coefficient are less than 22*Q.
/// NTT 域内多项式的逐点乘法，并将结果多项式乘以 2^{-32}。
/// 如果输入系数小于 22*Q，则输出系数小于 2*Q。
/// 
/// Arguments / 参数: 
/// - self: result polynomial (modified in place) / 结果多项式（原地修改）
/// - other: polynomial to multiply with / 要相乘的多项式
pub fn Poly::pointwise_montgomery(c : Poly, a : Poly, b : Poly) -> Unit {
  for i in 0..<N {
    c.coeffs[i] = montgomery_reduce(
      a.coeffs[i].to_int64() * b.coeffs[i].to_int64(),
    )
  }
}

///|
/// For all coefficients c of the input polynomial,
/// compute c0, c1 such that c mod Q = c1*2^D + c0
/// with -2^{D-1} < c0 <= 2^{D-1}. Assumes coefficients to be
/// standard representatives.
pub fn Poly::power2round(self : Poly, a0 : Poly) -> Unit {
  for i in 0..<N {
    let (low, high) = power2round(self.coeffs[i])
    self.coeffs[i] = high
    a0.coeffs[i] = low
  }
}

///|
/// For all coefficients c of the input polynomial,
/// compute high and low bits c0, c1 such c mod Q = c1*ALPHA + c0
/// with -ALPHA/2 < c0 <= ALPHA/2 except c1 = (Q-1)/ALPHA where we
/// set c1 = 0 and -ALPHA/2 <= c0 = c mod Q - Q < 0.
/// Assumes coefficients to be standard representatives.
/// 对于输入多项式的所有系数 c，计算高位和低位 c0, c1，
/// 使得 c mod Q = c1*ALPHA + c0，其中 -ALPHA/2 < c0 <= ALPHA/2，
/// 除了当 c1 = (Q-1)/ALPHA 时，我们设置 c1 = 0 且 -ALPHA/2 <= c0 = c mod Q - Q < 0。
/// 假设系数为标准代表元。
/// 
/// Arguments / 参数: 
/// - self: input polynomial, gets high bits (modified in place) / 输入多项式，获得高位（原地修改）
/// - other: output polynomial for low bits / 低位的输出多项式
pub fn Poly::decompose(self : Poly, low : Poly) -> Unit {
  for i in 0..<N {
    let (a0, a1) = decompose(self.coeffs[i])
    self.coeffs[i] = a1
    low.coeffs[i] = a0
  }
}

///|
/// Compute hint polynomial. The coefficients of which indicate
/// whether the low bits of the corresponding coefficient of
/// the input polynomial overflow into the high bits.
/// 计算提示多项式。其系数指示输入多项式对应系数的低位
/// 是否溢出到高位。
/// 
/// Arguments / 参数: 
/// - h: output hint polynomial / 输出提示多项式
/// - a0: low bits polynomial / 低位多项式
/// - a1: high bits polynomial / 高位多项式
/// 
/// Returns / 返回: Number of 1's in hint polynomial / 提示多项式中 1 的数量
pub fn Poly::make_hint(h : Poly, a0 : Poly, a1 : Poly) -> Int {
  let mut s = 0
  for i in 0..<N {
    h.coeffs[i] = make_hint(a0.coeffs[i], a1.coeffs[i]).to_int()
    s += h.coeffs[i]
  }
  s
}

///|
/// Use hint polynomial to correct the high bits of a polynomial.
/// 使用提示多项式来修正多项式的高位。
/// 
/// Arguments / 参数: 
/// - self: input/output polynomial with corrected high bits / 具有修正高位的输入/输出多项式
/// - h: hint polynomial / 提示多项式
pub fn Poly::use_hint(self : Poly, h : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = use_hint(self.coeffs[i], h.coeffs[i].to_byte())
  }
}

///|
/// Check infinity norm of polynomial against given bound.
/// Assumes input coefficients to be standard representatives.
/// Returns 0 if norm is strictly smaller than B and 1 otherwise.
/// 检查多项式的无穷范数是否超过给定界限。
/// 假设输入系数为标准代表元。
/// 如果范数严格小于 B 则返回 0，否则返回 1。
/// 
/// Arguments / 参数: 
/// - self: polynomial to check / 要检查的多项式
/// - b: bound to check against / 要检查的界限
/// 
/// Returns / 返回: 0 if all coefficients have absolute value < b, 1 otherwise
///                0 如果所有系数的绝对值 < b，否则返回 1
pub fn Poly::chknorm(self : Poly, b : Int) -> Byte {
  // It is ok to leak which coefficient violates the bound since
  // the probability for each coefficient is independent of secret
  // data but we must not leak the sign of the centralized representative.
  // 可以泄露哪个系数违反了界限，因为每个系数的概率与秘密数据无关，
  // 但我们不能泄露中心化代表元的符号。
  let mut t = 0
  if b > (Q - 1) / 8 {
    return 1
  }
  for coeff in self.coeffs {
    // Absolute value of centralized representative
    // 中心化代表元的绝对值
    t = coeff >> 31
    t = coeff - (t & (2 * coeff))
    if t >= b {
      return 1
    }
  }
  0
}

///|
/// Sample uniformly random coefficients in [0, Q-1] by
/// performing rejection sampling on array of random bytes.
/// Returns number of sampled coefficients. Can be smaller than len if not enough
/// random bytes were given.
/// 通过对随机字节数组执行拒绝采样来采样 [0, Q-1] 范围内的均匀随机系数。
/// 返回采样系数的数量。如果给定的随机字节不够，可能小于 len。
/// 
/// Arguments / 参数: 
/// - a: output array for coefficients / 系数的输出数组
/// - len: number of coefficients to sample / 要采样的系数数量
/// - buf: input buffer of random bytes / 随机字节的输入缓冲区
/// - buflen: length of input buffer / 输入缓冲区的长度
/// 
/// Returns / 返回: number of coefficients successfully sampled / 成功采样的系数数量
pub fn rej_uniform(
  a : MutArrayView[Int],
  len : Int,
  buf : Array[Byte],
  buflen : Int,
) -> Int {
  let mut cnt = 0 // Counter for accepted samples / 接受样本的计数器
  let mut pos = 0 // Position in input buffer / 输入缓冲区中的位置
  let mut t = 0U // Temporary variable for 24-bit value / 24位值的临时变量
  while cnt < len && pos + 3 <= buflen {
    // Read 24 bits (3 bytes) in little-endian format
    // 以小端格式读取 24 位（3 字节）
    t = buf[pos].to_uint()
    pos = pos + 1
    t = t | (buf[pos].to_uint() << 8)
    pos = pos + 1
    t = t | (buf[pos].to_uint() << 16)
    pos = pos + 1
    t = t & 0x7FFFFF

    // Accept sample if it's in the valid range [0, Q-1]
    // 如果样本在有效范围 [0, Q-1] 内则接受
    if t < Q.reinterpret_as_uint() {
      a.set(cnt, t.reinterpret_as_int())
      cnt = cnt + 1
    }
  }
  cnt
}

///|
/// Defines the number of 128-byte blocks needed to generate sufficient random
/// bytes for uniform polynomial sampling.
///
/// This constant calculates the minimum number of SHAKE128 output blocks
/// required to ensure that rejection sampling can successfully generate all N
/// coefficients for a polynomial with high probability. The calculation
/// accounts for the overhead in rejection sampling where not all random bytes
/// result in valid coefficients in the range \[0, Q-1].
///
/// The value is computed as ⌈768 / STREAM128\_BLOCKBYTES⌉, where 768 bytes
/// provides enough random material for the rejection sampling algorithm to
/// succeed with very high probability.
///
pub const POLY_UNIFORM_NBLOCKS : UInt = (768 + STREAM128_BLOCKBYTES - 1) /
  STREAM128_BLOCKBYTES

///|
/// Samples uniformly random coefficients in \[0, Q-1] for the polynomial using
/// rejection sampling on a pseudo-random stream.
///
/// Parameters:
///
/// * `self` : The polynomial to fill with uniform random coefficients.
/// * `seed` : The seed bytes used to initialize the pseudo-random stream.
/// * `nonce` : A 16-bit nonce value used along with the seed for stream
///   initialization.
///
/// Panics if the rejection sampling fails to generate enough coefficients after
/// multiple attempts (this should be extremely unlikely with proper
/// randomness).
pub fn Poly::uniform(self : Poly, seed : Array[Byte], nonce : UInt16) -> Unit {
  let mut buflen = (POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES).reinterpret_as_int()
  let buf : Array[Byte] = Array::make(buflen + 2, 0)
  let state = KeccakState::default()
  stream128_init(state, seed, nonce)
  stream128_squeezeblocks(buf.mut_view(), POLY_UNIFORM_NBLOCKS.to_uint64(), state)
  let mut cnt = rej_uniform(self.coeffs.mut_view(), N, buf, buflen)
  let mut off = 0
  while cnt.reinterpret_as_uint() < N.reinterpret_as_uint() {
    off = buflen % 3
    for i in 0..<off {
      buf[i] = buf[buflen - off + i]
    }
    buflen = STREAM128_BLOCKBYTES.reinterpret_as_int() + off
    stream128_squeezeblocks(buf.mut_view(start=off), 1, state)
    cnt = cnt + rej_uniform(self.coeffs.mut_view(start=cnt), N - cnt, buf, buflen)
  }
}

///|
/// Performs rejection sampling on a buffer of random bytes to generate
/// coefficients in the range \[-eta, eta] for Dilithium polynomial operations.
///
/// This function extracts 4-bit values from each byte in the input buffer and
/// uses rejection sampling to convert them into coefficients within the valid
/// range based on the eta parameter from the Dilithium context. For eta=2, it
/// uses modular arithmetic to map values \[0,14] to \[-2,2]. For eta=4, it
/// directly maps values \[0,8] to \[-4,4].
///
/// Parameters:
///
/// * `a` : The output array view where accepted coefficients will be stored.
/// * `len` : The maximum number of coefficients to generate.
/// * `buf` : The input buffer containing random bytes for sampling.
/// * `buflen` : The length of the input buffer in bytes.
///
/// Returns the number of coefficients successfully generated and stored in the
/// output array.
///
pub fn rej_eta(
  a : MutArrayView[Int],
  len : Int,
  buf : Array[Byte],
  buflen : Int,
) -> UInt {
  let mut cnt = 0
  let mut pos = 0
  let mut t0 = 0U
  let mut t1 = 0U
  let eta = dilithium_context.get_params_set().eta
  while cnt < len && pos < buflen {
    t0 = (buf[pos] & 0x0F).to_uint()
    t1 = (buf[pos] >> 4).to_uint()
    pos = pos + 1
    if eta == 2 {
      if t0 < 15 {
        t0 = t0 - ((205 * t0) >> 10) * 5
        a.set(cnt, 2 - t0.reinterpret_as_int())
        cnt += 1
      }
      if t1 < 15 && cnt < len {
        t1 = t1 - ((205 * t1) >> 10) * 5
        a.set(cnt, 2 - t1.reinterpret_as_int())
        cnt = cnt + 1
      }
    } else if eta == 4 {
      if t0 < 9 {
        a.set(cnt, 4 - t0.reinterpret_as_int())
        cnt = cnt + 1
      }
      if t1 < 9 && cnt < len {
        a.set(cnt, 4 - t1.reinterpret_as_int())
        cnt = cnt + 1
      }
    }
  }
  cnt.reinterpret_as_uint()
}

///|
/// Samples uniformly random coefficients in the range \[-η, η] for the
/// polynomial using rejection sampling on a pseudo-random stream.
///
/// This function uses the SHAKE256 extendable-output function to generate
/// random bytes, then applies rejection sampling to obtain coefficients within
/// the required range. The number of blocks to generate depends on the η
/// parameter from the current Dilithium parameter set.
///
/// Parameters:
///
/// * `self` : The polynomial to fill with uniformly random coefficients in
///   \[-η, η].
/// * `seed` : The seed bytes used to initialize the SHAKE256 pseudo-random
///   stream.
/// * `nonce` : A 16-bit nonce value used along with the seed for stream
///   initialization to ensure different outputs for the same seed.
///
pub fn Poly::poly_uniform_eta(
  self : Poly,
  seed : Array[Byte],
  nonce : UInt16,
) -> Unit {
  let poly_uniform_eta_nblocks : UInt = if dilithium_context.get_params_set().eta ==
    2 {
    (136 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
  } else {
    (227 + STREAM256_BLOCKBYTES - 1) / STREAM256_BLOCKBYTES
  }
  let buflen = (poly_uniform_eta_nblocks * STREAM256_BLOCKBYTES).reinterpret_as_int()
  let buf : Array[Byte] = Array::make(buflen, 0)
  let state = KeccakState::default()
  stream256_init(state, seed, nonce)
  stream256_squeezeblocks(buf, poly_uniform_eta_nblocks.to_uint64(), state)
  let mut cnt = rej_eta(self.coeffs.mut_view(), N, buf, buflen)
  while cnt < N.reinterpret_as_uint() {
    stream256_squeezeblocks(buf, 1, state)
    cnt += rej_eta(
      self.coeffs.mut_view(start=cnt.reinterpret_as_int()),
      N - cnt.reinterpret_as_int(),
      buf,
      STREAM256_BLOCKBYTES.reinterpret_as_int(),
    )
  }
}

///|
/// Sample polynomial with uniformly random coefficients
/// in [-(GAMMA1 - 1), GAMMA1 - 1] by performing rejection
/// sampling on output stream of SHAKE256(seed|nonce)
/// or AES256CTR(seed,nonce).
pub fn Poly::uniform_gamma1(
  self : Poly,
  seed : Array[Byte],
  nonce : UInt16,
) -> Unit {
  let poly_uniform_gamma1_nblocks = dilithium_context.get_params_set().poly_uniform_gamma1_nblocks
  let buflen = (poly_uniform_gamma1_nblocks * STREAM256_BLOCKBYTES).reinterpret_as_int()
  let buf : Array[Byte] = Array::make(buflen, 0)
  let state = KeccakState::default()
  stream256_init(state, seed, nonce)
  stream256_squeezeblocks(buf, poly_uniform_gamma1_nblocks.to_uint64(), state)
  self.unpack_z(buf)
}

///|
fn poly_array_to_bytes(poly_array : Array[Int]) -> Array[Byte] {
  let bytes_array : Array[Byte] = Array::make(poly_array.length() * 4, 0)
  for i in 0..<poly_array.length() {
    let n = poly_array[i]
    bytes_array[i * 4] = (n & 0xFF).to_byte()
    bytes_array[i * 4 + 1] = ((n >> 8) & 0xFF).to_byte()
    bytes_array[i * 4 + 2] = ((n >> 16) & 0xFF).to_byte()
    bytes_array[i * 4 + 3] = ((n >> 24) & 0xFF).to_byte()
  }
  bytes_array
}

///|
/// Generates a challenge polynomial using the SHAKE256 hash function,
/// implementing the H function from the Dilithium signature scheme.
///
/// This method samples a polynomial with exactly `tau` nonzero coefficients,
/// each being either -1 or +1. The polynomial is used as part of the
/// cryptographic challenge in the Dilithium digital signature algorithm. The
/// sampling process uses rejection sampling on the SHAKE256 output stream to
/// ensure uniform distribution.
///
/// Parameters:
///
/// * `self` : The polynomial to be filled with challenge coefficients. All
///   coefficients will be set to 0 initially, then `tau` positions will be set
///   to either -1 or +1.
/// * `seed` : A byte array used as the seed for the SHAKE256 hash function.
///   This seed determines the challenge polynomial generation.
///
/// The method works by:
///
/// 1. Initializing all polynomial coefficients to zero
/// 2. Using SHAKE256 to generate pseudorandom bytes from the seed
/// 3. Extracting sign bits for the nonzero coefficients
/// 4. Using rejection sampling to select `tau` distinct positions
/// 5. Setting the selected positions to -1 or +1 based on the extracted sign
/// bits
///
/// The resulting polynomial will have exactly `tau` nonzero coefficients
/// distributed uniformly at random positions, with each nonzero coefficient
/// being either -1 or +1 with equal probability.
///
pub fn Poly::challenge(self : Poly, seed : Array[Byte]) -> Unit {
  let tau = dilithium_context.get_params_set().tau
  let mut signs : UInt64 = 0
  let buf : Array[Byte] = Array::make(SHAKE256_RATE.reinterpret_as_int(), 0)
  let state = KeccakState::default()

  // The nonce for challenge is not specified, using 0 as a default.
  shake256_absorb(state, seed, SEEDBYTES.reinterpret_as_uint())
  shake256_finalize(state)
  shake256_squeezeblocks(buf, 1, state)
  for i in 0..<8 {
    signs = signs | (buf[i].to_uint64() << (8 * i))
  }
  let mut pos = 8
  for i in 0..<N {
    self.coeffs[i] = 0
  }
  for i in (N - tau)..<N {
    let mut b = 0
    while true {
      if pos >= SHAKE256_RATE.reinterpret_as_int() {
        stream256_squeezeblocks(buf, 1, state)
        pos = 0
      }
      b = buf[pos].to_int()
      pos += 1
      if b.reinterpret_as_uint() <= i.reinterpret_as_uint() {
        break
      }
    }
    self.coeffs[i] = self.coeffs[b]
    self.coeffs[b] = 1 - 2 * (signs & 1).to_int()
    signs = signs >> 1
  }
}

///|
/// Encodes a polynomial with coefficients in the range \[-ETA, ETA] into a
/// compact byte array representation.
///
/// This function performs bit-packing to efficiently store polynomial
/// coefficients that are bounded by the ETA parameter. The packing strategy
/// depends on the specific ETA value used in the current Dilithium parameter
/// set. For ETA=2, coefficients are packed using 3 bits each with 8
/// coefficients packed into 3 bytes. For ETA=4, coefficients are packed using 4
/// bits each with 2 coefficients packed into 1 byte.
///
/// Parameters:
///
/// * `self` : The polynomial whose coefficients will be packed. Coefficients
///   are assumed to lie in the range \[Q-ETA, Q+ETA].
///
/// Returns a byte array containing the bit-packed representation of the
/// polynomial coefficients. The size of the returned array depends on the ETA
/// parameter from the current Dilithium parameter set.
///
pub fn Poly::pack_eta(self : Poly) -> Array[Byte] {
  let eta = dilithium_context.get_params_set().eta
  let polyeta_packedbytes = dilithium_context.get_params_set().polyeta_packedbytes
  let t = Array::make(8, 0)
  let r : Array[Byte] = Array::make(polyeta_packedbytes, 0)
  if eta == 2 {
    for i in 0..<(N / 8) {
      t[0] = eta - self.coeffs[8 * i + 0]
      t[1] = eta - self.coeffs[8 * i + 1]
      t[2] = eta - self.coeffs[8 * i + 2]
      t[3] = eta - self.coeffs[8 * i + 3]
      t[4] = eta - self.coeffs[8 * i + 4]
      t[5] = eta - self.coeffs[8 * i + 5]
      t[6] = eta - self.coeffs[8 * i + 6]
      t[7] = eta - self.coeffs[8 * i + 7]
      r[3 * i + 0] = (t[0] | (t[1] << 3) | (t[2] << 6)).to_byte()
      r[3 * i + 1] = ((t[2] >> 2) | (t[3] << 1) | (t[4] << 4) | (t[5] << 7)).to_byte()
      r[3 * i + 2] = ((t[5] >> 1) | (t[6] << 2) | (t[7] << 5)).to_byte()
    }
  } else {
    for i in 0..<(N / 2) {
      t[0] = eta - self.coeffs[2 * i + 0]
      t[1] = eta - self.coeffs[2 * i + 1]
      r[i] = (t[0] | (t[1] << 4)).to_byte()
    }
  }
  r
}

///|
/// Unpacks a polynomial with small coefficients from a packed byte
/// representation.
///
/// Parameters:
///
/// * `self` : The polynomial to store the unpacked coefficients. Its
///   coefficients will be modified in place.
/// * `a` : The packed byte array containing the encoded polynomial
///   coefficients.
///
/// Panics:
///
/// * This function will panic if the length of the input byte array `a` doesn't
///   match the expected size for the current eta parameter.
///
/// The unpacking process depends on the eta value from the Dilithium parameter
/// set:
///
/// * For eta = 2: Each group of 3 bytes encodes 8 polynomial coefficients using
///   3-bit values
/// * For eta = 4: Each byte encodes 2 polynomial coefficients using 4-bit
///   values
///
/// After extracting the raw values, the function transforms them from the range
/// \[0, 2\*eta] back to the coefficient range \[-eta, eta] by computing `eta -
/// extracted_value` for each coefficient.
///
/// This function is the inverse operation of `Poly::pack_eta`.
///
pub fn Poly::unpack_eta(self : Poly, a : Array[Byte]) -> Unit {
  let eta = dilithium_context.get_params_set().eta
  if eta == 2 {
    for i in 0..<(N / 8) {
      self.coeffs[8 * i + 0] = a[3 * i + 0].to_int() & 0x07
      self.coeffs[8 * i + 1] = (a[3 * i + 0].to_int() >> 3) & 0x07
      self.coeffs[8 * i + 2] = (
          (a[3 * i + 0].to_int() >> 6) | (a[3 * i + 1].to_int() << 2)
        ) &
        0x07
      self.coeffs[8 * i + 3] = (a[3 * i + 1].to_int() >> 1) & 0x07
      self.coeffs[8 * i + 4] = (a[3 * i + 1].to_int() >> 4) & 0x07
      self.coeffs[8 * i + 5] = (
          (a[3 * i + 1].to_int() >> 7) | (a[3 * i + 2].to_int() << 1)
        ) &
        0x07
      self.coeffs[8 * i + 6] = (a[3 * i + 2].to_int() >> 2) & 0x07
      self.coeffs[8 * i + 7] = (a[3 * i + 2].to_int() >> 5) & 0x07
      self.coeffs[8 * i + 0] = eta - self.coeffs[8 * i + 0]
      self.coeffs[8 * i + 1] = eta - self.coeffs[8 * i + 1]
      self.coeffs[8 * i + 2] = eta - self.coeffs[8 * i + 2]
      self.coeffs[8 * i + 3] = eta - self.coeffs[8 * i + 3]
      self.coeffs[8 * i + 4] = eta - self.coeffs[8 * i + 4]
      self.coeffs[8 * i + 5] = eta - self.coeffs[8 * i + 5]
      self.coeffs[8 * i + 6] = eta - self.coeffs[8 * i + 6]
      self.coeffs[8 * i + 7] = eta - self.coeffs[8 * i + 7]
    }
  } else {
    for i in 0..<(N / 2) {
      self.coeffs[2 * i + 0] = a[i].to_int() & 0x0F
      self.coeffs[2 * i + 1] = a[i].to_int() >> 4
      self.coeffs[2 * i + 0] = eta - self.coeffs[2 * i + 0]
      self.coeffs[2 * i + 1] = eta - self.coeffs[2 * i + 1]
    }
  }
}

///|
/// Bit-packs a polynomial t1 with coefficients that fit within 10 bits into a
/// compact byte array representation.
///
/// Parameters:
///
/// * `self` : The polynomial containing coefficients to be packed. Input
///   coefficients are assumed to be standard representatives fitting within 10
///   bits.
///
/// Returns a byte array containing the bit-packed representation of the
/// polynomial. The output array has length `N / 4 * 5` bytes, where every group
/// of 4 coefficients is packed into 5 bytes.
///
/// Example:
///
/// ```moonbit
/// let poly = Poly::new()
/// // Assume poly has been populated with valid coefficients
///
/// let packed_bytes = poly.pack_t1()
/// ```
///
pub fn Poly::pack_t1(self : Poly) -> Array[Byte] {
  let r : Array[Byte] = Array::make(N / 4 * 5, 0)
  for i in 0..<(N / 4) {
    r[5 * i + 0] = (self.coeffs[4 * i + 0] >> 0).to_byte()
    r[5 * i + 1] = ((self.coeffs[4 * i + 0] >> 8) |
    (self.coeffs[4 * i + 1] << 2)).to_byte()
    r[5 * i + 2] = ((self.coeffs[4 * i + 1] >> 6) |
    (self.coeffs[4 * i + 2] << 4)).to_byte()
    r[5 * i + 3] = ((self.coeffs[4 * i + 2] >> 4) |
    (self.coeffs[4 * i + 3] << 6)).to_byte()
    r[5 * i + 4] = (self.coeffs[4 * i + 3] >> 2).to_byte()
  }
  r
}

///|
/// Unpacks polynomial coefficients from a byte array, where each coefficient is
/// stored using 10 bits.
///
/// Parameters:
///
/// * `self` : The polynomial to store the unpacked coefficients in.
/// * `a` : The byte array containing the packed polynomial coefficients. Must
///   contain at least `5 * (N / 4)` bytes where every 5 consecutive bytes
///   encode 4 coefficients.
///
/// Panics:
///
/// Panics if the byte array `a` does not contain enough bytes for the expected
/// number of coefficients, or if array bounds are exceeded during the unpacking
/// process.
///
pub fn Poly::unpack_t1(self : Poly, a : Array[Byte]) -> Unit {
  for i in 0..<(N / 4) {
    self.coeffs[4 * i + 0] = (
        (a[5 * i + 0].to_int() >> 0) | (a[5 * i + 1].to_int() << 8)
      ) &
      0x3FF
    self.coeffs[4 * i + 1] = (
        (a[5 * i + 1].to_int() >> 2) | (a[5 * i + 2].to_int() << 6)
      ) &
      0x3FF
    self.coeffs[4 * i + 2] = (
        (a[5 * i + 2].to_int() >> 4) | (a[5 * i + 3].to_int() << 4)
      ) &
      0x3FF
    self.coeffs[4 * i + 3] = (
        (a[5 * i + 3].to_int() >> 6) | (a[5 * i + 4].to_int() << 2)
      ) &
      0x3FF
  }
}

///|
/// Serializes polynomial coefficients with values in the range \[-2^{D-1},
/// 2^{D-1}] into a compact byte array representation.
///
/// This function performs bit-packing of polynomial coefficients by first
/// transforming them to unsigned values using the formula `D_SHL -
/// coefficient`, where `D_SHL = 2^{D-1}`. The transformed coefficients are then
/// packed into bytes using a custom bit-packing scheme that processes 8
/// coefficients at a time and produces 13 bytes of output per group.
///
/// Parameters:
///
/// * `self` : The polynomial whose coefficients will be packed. Coefficients
///   must be in the range \[-2^{D-1}, 2^{D-1}].
///
/// Returns a byte array containing the bit-packed representation of the
/// polynomial coefficients. The output size is `N / 8 * 13` bytes, where `N` is
/// the number of coefficients in the polynomial.
///
pub fn Poly::pack_t0(self : Poly) -> Array[Byte] {
  let t = Array::make(8, 0)
  let r : Array[Byte] = Array::make(N / 8 * 13, 0)
  for i in 0..<(N / 8) {
    t[0] = D_SHL - self.coeffs[8 * i + 0]
    t[1] = D_SHL - self.coeffs[8 * i + 1]
    t[2] = D_SHL - self.coeffs[8 * i + 2]
    t[3] = D_SHL - self.coeffs[8 * i + 3]
    t[4] = D_SHL - self.coeffs[8 * i + 4]
    t[5] = D_SHL - self.coeffs[8 * i + 5]
    t[6] = D_SHL - self.coeffs[8 * i + 6]
    t[7] = D_SHL - self.coeffs[8 * i + 7]
    r[13 * i + 0] = t[0].to_byte()
    r[13 * i + 1] = ((t[0] >> 8) | (t[1] << 5)).to_byte()
    r[13 * i + 2] = (t[1] >> 3).to_byte()
    r[13 * i + 3] = ((t[1] >> 11) | (t[2] << 2)).to_byte()
    r[13 * i + 4] = ((t[2] >> 6) | (t[3] << 7)).to_byte()
    r[13 * i + 5] = (t[3] >> 1).to_byte()
    r[13 * i + 6] = ((t[3] >> 9) | (t[4] << 4)).to_byte()
    r[13 * i + 7] = (t[4] >> 4).to_byte()
    r[13 * i + 8] = ((t[4] >> 12) | (t[5] << 1)).to_byte()
    r[13 * i + 9] = ((t[5] >> 7) | (t[6] << 6)).to_byte()
    r[13 * i + 10] = (t[6] >> 2).to_byte()
    r[13 * i + 11] = ((t[6] >> 10) | (t[7] << 3)).to_byte()
    r[13 * i + 12] = (t[7] >> 5).to_byte()
  }
  r
}

///|
/// Unpacks polynomial t0 from its byte array representation with coefficients
/// in the range ]-2^{D-1}, 2^{D-1}].
///
/// Performs the inverse operation of `pack_t0`, reconstructing polynomial
/// coefficients from their
/// bit-packed byte representation. Each group of 8 coefficients is packed into
/// 13 bytes using
/// a complex bit-packing scheme. The function extracts 13-bit values from the
/// byte array,
/// masks them to ensure they stay within the valid range, and then transforms
/// them back to
/// the signed coefficient representation by subtracting from D\_SHL (2^{D-1}).
///
/// Parameters:
///
/// * `self` : The polynomial to be modified with the unpacked coefficients.
/// * `a` : The byte array containing the packed polynomial data. Must have
///   length N/8 \* 13 bytes.
///
/// Panics if the input byte array `a` does not have the expected length of N/8
/// \* 13 bytes, which would cause an index out of bounds error during
/// unpacking.
///
pub fn Poly::unpack_t0(self : Poly, a : Array[Byte]) -> Unit {
  for i in 0..<(N / 8) {
    self.coeffs[8 * i + 0] = a[13 * i + 0].to_int() |
      (a[13 * i + 1].to_int() << 8)
    self.coeffs[8 * i + 0] = self.coeffs[8 * i + 0] & 0x1FFF
    self.coeffs[8 * i + 1] = (a[13 * i + 1].to_int() >> 5) |
      (a[13 * i + 2].to_int() << 3) |
      (a[13 * i + 3].to_int() << 11)
    self.coeffs[8 * i + 1] = self.coeffs[8 * i + 1] & 0x1FFF
    self.coeffs[8 * i + 2] = (a[13 * i + 3].to_int() >> 2) |
      (a[13 * i + 4].to_int() << 6)
    self.coeffs[8 * i + 2] = self.coeffs[8 * i + 2] & 0x1FFF
    self.coeffs[8 * i + 3] = (a[13 * i + 4].to_int() >> 7) |
      (a[13 * i + 5].to_int() << 1) |
      (a[13 * i + 6].to_int() << 9)
    self.coeffs[8 * i + 3] = self.coeffs[8 * i + 3] & 0x1FFF
    self.coeffs[8 * i + 4] = (a[13 * i + 6].to_int() >> 4) |
      (a[13 * i + 7].to_int() << 4) |
      (a[13 * i + 8].to_int() << 12)
    self.coeffs[8 * i + 4] = self.coeffs[8 * i + 4] & 0x1FFF
    self.coeffs[8 * i + 5] = (a[13 * i + 8].to_int() >> 1) |
      (a[13 * i + 9].to_int() << 7)
    self.coeffs[8 * i + 5] = self.coeffs[8 * i + 5] & 0x1FFF
    self.coeffs[8 * i + 6] = (a[13 * i + 9].to_int() >> 6) |
      (a[13 * i + 10].to_int() << 2) |
      (a[13 * i + 11].to_int() << 10)
    self.coeffs[8 * i + 6] = self.coeffs[8 * i + 6] & 0x1FFF
    self.coeffs[8 * i + 7] = (a[13 * i + 11].to_int() >> 3) |
      (a[13 * i + 12].to_int() << 5)
    self.coeffs[8 * i + 7] = self.coeffs[8 * i + 7] & 0x1FFF
    self.coeffs[8 * i + 0] = D_SHL - self.coeffs[8 * i + 0]
    self.coeffs[8 * i + 1] = D_SHL - self.coeffs[8 * i + 1]
    self.coeffs[8 * i + 2] = D_SHL - self.coeffs[8 * i + 2]
    self.coeffs[8 * i + 3] = D_SHL - self.coeffs[8 * i + 3]
    self.coeffs[8 * i + 4] = D_SHL - self.coeffs[8 * i + 4]
    self.coeffs[8 * i + 5] = D_SHL - self.coeffs[8 * i + 5]
    self.coeffs[8 * i + 6] = D_SHL - self.coeffs[8 * i + 6]
    self.coeffs[8 * i + 7] = D_SHL - self.coeffs[8 * i + 7]
  }
}

///|
/// Bit-pack polynomial z with coefficients
/// in [-(GAMMA1 - 1), GAMMA1 - 1].
/// Input coefficients are assumed to be standard representatives.*
pub fn Poly::pack_z(self : Poly) -> Array[Byte] {
  let gamma1 = dilithium_context.get_params_set().gamma1
  let t = Array::make(4, 0)
  if gamma1 == 1 << 17 {
    let r : Array[Byte] = Array::make(N / 4 * 9, 0)
    for i in 0..<(N / 4) {
      t[0] = gamma1 - self.coeffs[4 * i + 0]
      t[1] = gamma1 - self.coeffs[4 * i + 1]
      t[2] = gamma1 - self.coeffs[4 * i + 2]
      t[3] = gamma1 - self.coeffs[4 * i + 3]
      r[9 * i + 0] = t[0].to_byte()
      r[9 * i + 1] = (t[0] >> 8).to_byte()
      r[9 * i + 2] = ((t[0] >> 16) | (t[1] << 2)).to_byte()
      r[9 * i + 3] = (t[1] >> 6).to_byte()
      r[9 * i + 4] = ((t[1] >> 14) | (t[2] << 4)).to_byte()
      r[9 * i + 5] = (t[2] >> 4).to_byte()
      r[9 * i + 6] = ((t[2] >> 12) | (t[3] << 6)).to_byte()
      r[9 * i + 7] = (t[3] >> 2).to_byte()
      r[9 * i + 8] = (t[3] >> 10).to_byte()
    }
    r
  } else {
    // gamma1 == (1 << 19)
    let r : Array[Byte] = Array::make(N / 2 * 5, 0)
    for i in 0..<(N / 2) {
      t[0] = gamma1 - self.coeffs[2 * i + 0]
      t[1] = gamma1 - self.coeffs[2 * i + 1]
      r[5 * i + 0] = t[0].to_byte()
      r[5 * i + 1] = (t[0] >> 8).to_byte()
      r[5 * i + 2] = ((t[0] >> 16) | (t[1] << 4)).to_byte()
      r[5 * i + 3] = (t[1] >> 4).to_byte()
      r[5 * i + 4] = (t[1] >> 12).to_byte()
    }
    r
  }
}

///|
/// Unpacks a polynomial from its bit-packed byte array representation,
/// restoring coefficients in the range \[-(GAMMA1 - 1), GAMMA1 - 1].
///
/// This function performs the inverse operation of `pack_z`, decoding a
/// compressed polynomial representation back into standard coefficient form.
/// The unpacking process depends on the GAMMA1 parameter from the Dilithium
/// context, supporting both GAMMA1 = 2^17 (131072) and GAMMA1 = 2^19 (524288)
/// parameter sets with different bit layouts.
///
/// For GAMMA1 = 2^17:
///
/// * Uses 18-bit representation per coefficient (mask 0x3FFFF)
/// * Packs 4 coefficients into 9 bytes (4.5 bytes per coefficient)
/// * Each group of 4 coefficients requires 72 bits total
///
/// For GAMMA1 = 2^19:
///
/// * Uses 20-bit representation per coefficient (mask 0xFFFFF)
/// * Packs 2 coefficients into 5 bytes (2.5 bytes per coefficient)
/// * Each group of 2 coefficients requires 40 bits total
///
/// After bit extraction, coefficients are converted from their packed
/// representation to standard form by computing GAMMA1 - packed\_value,
/// ensuring the result lies in the correct range.
///
/// Parameters:
///
/// * `self` : The polynomial whose coefficients will be modified in place with
///   the unpacked values.
/// * `a` : The byte array containing the bit-packed polynomial data.
///
pub fn Poly::unpack_z(self : Poly, a : Array[Byte]) -> Unit {
  let gamma1 = dilithium_context.get_params_set().gamma1
  if gamma1 == 1 << 17 {
    for i in 0..<(N / 4) {
      self.coeffs[4 * i + 0] = a[9 * i + 0].to_int() |
        (a[9 * i + 1].to_int() << 8) |
        (a[9 * i + 2].to_int() << 16)
      self.coeffs[4 * i + 0] = self.coeffs[4 * i + 0] & 0x3FFFF
      self.coeffs[4 * i + 1] = (a[9 * i + 2].to_int() >> 2) |
        (a[9 * i + 3].to_int() << 6) |
        (a[9 * i + 4].to_int() << 14)
      self.coeffs[4 * i + 1] = self.coeffs[4 * i + 1] & 0x3FFFF
      self.coeffs[4 * i + 2] = (a[9 * i + 4].to_int() >> 4) |
        (a[9 * i + 5].to_int() << 4) |
        (a[9 * i + 6].to_int() << 12)
      self.coeffs[4 * i + 2] = self.coeffs[4 * i + 2] & 0x3FFFF
      self.coeffs[4 * i + 3] = (a[9 * i + 6].to_int() >> 6) |
        (a[9 * i + 7].to_int() << 2) |
        (a[9 * i + 8].to_int() << 10)
      self.coeffs[4 * i + 3] = self.coeffs[4 * i + 3] & 0x3FFFF
      self.coeffs[4 * i + 0] = gamma1 - self.coeffs[4 * i + 0]
      self.coeffs[4 * i + 1] = gamma1 - self.coeffs[4 * i + 1]
      self.coeffs[4 * i + 2] = gamma1 - self.coeffs[4 * i + 2]
      self.coeffs[4 * i + 3] = gamma1 - self.coeffs[4 * i + 3]
    }
  } else {
    // gamma1 == (1 << 19)
    for i in 0..<(N / 2) {
      self.coeffs[2 * i + 0] = a[5 * i + 0].to_int() |
        (a[5 * i + 1].to_int() << 8) |
        (a[5 * i + 2].to_int() << 16)
      self.coeffs[2 * i + 0] = self.coeffs[2 * i + 0] & 0xFFFFF
      self.coeffs[2 * i + 1] = (a[5 * i + 2].to_int() >> 4) |
        (a[5 * i + 3].to_int() << 4) |
        (a[5 * i + 4].to_int() << 12)
      self.coeffs[2 * i + 1] = self.coeffs[2 * i + 1] & 0xFFFFF
      self.coeffs[2 * i + 0] = gamma1 - self.coeffs[2 * i + 0]
      self.coeffs[2 * i + 1] = gamma1 - self.coeffs[2 * i + 1]
    }
  }
}

///|
/// Bit-packs polynomial w1 coefficients into a compact byte array
/// representation.
///
/// Parameters:
///
/// * `self` : The polynomial containing coefficients in the range \[0, 15] that
///   are assumed to be standard representatives.
///
/// Returns a byte array containing the bit-packed representation of the
/// polynomial coefficients. The size of the returned array depends on the
/// gamma2 parameter: N/4 \* 3 bytes when gamma2 equals (Q-1)/88, or N/2 bytes
/// otherwise.
///
pub fn Poly::pack_w1(self : Poly) -> Array[Byte] {
  let gamma2 = dilithium_context.get_params_set().gamma2
  if gamma2 == (Q - 1) / 88 {
    let r : Array[Byte] = Array::make(N / 4 * 3, 0)
    for i in 0..<(N / 4) {
      r[3 * i + 0] = (self.coeffs[4 * i + 0] | (self.coeffs[4 * i + 1] << 6)).to_byte()
      r[3 * i + 1] = ((self.coeffs[4 * i + 1] >> 2) |
      (self.coeffs[4 * i + 2] << 4)).to_byte()
      r[3 * i + 2] = ((self.coeffs[4 * i + 2] >> 4) |
      (self.coeffs[4 * i + 3] << 2)).to_byte()
    }
    r
  } else {
    let r : Array[Byte] = Array::make(N / 2, 0)
    for i in 0..<(N / 2) {
      r[i] = (self.coeffs[2 * i + 0] | (self.coeffs[2 * i + 1] << 4)).to_byte()
    }
    r
  }
}
