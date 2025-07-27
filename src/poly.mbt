///| D_SHL = 2^{D-1}, used for power-of-2 rounding / D_SHL = 2^{D-1}，用于2的幂次舍入
const D_SHL : Int = 1 << (D - 1)

///| Polynomial structure containing an array of coefficients.
/// 包含系数数组的多项式结构。
pub struct Poly {
  coeffs : Array[Int] // Coefficient array / 系数数组
} derive(Show)

///| Default implementation for Poly - creates a polynomial with all zero coefficients.
/// Poly 的默认实现 - 创建所有系数为零的多项式。
impl Default for Poly with default() -> Poly {
  { coeffs: Array::make(N, 0) }
}

///| Create a new polynomial with all zero coefficients.
/// 创建一个所有系数为零的新多项式。
pub fn Poly::new() -> Poly {
  Poly::default()
}

///|
pub fn Poly::copy(self : Poly) -> Poly {
  { coeffs: self.coeffs.copy() }
}

///| Add polynomials. No modular reduction is performed.
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

///| Inplace reduction of all coefficients of polynomial to
/// representative in [0,2*Q].
/// 将多项式的所有系数原地约简到 [0,2*Q] 范围内的代表元。
pub fn Poly::reduce(self : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = reduce32(self.coeffs[i])
  }
}

///| For all coefficients of in/out polynomial add Q if
/// coefficient is negative.
/// 对于多项式的所有系数，如果系数为负则加上 Q。
pub fn Poly::caddq(self : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = caddq(self.coeffs[i])
  }
}

///| Subtract polynomials. Assumes coefficients of second input
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

///| Multiply polynomial by 2^D without modular reduction. Assumes
/// input coefficients to be less than 2^{32-D}.
/// 将多项式乘以 2^D，不执行模约简。假设输入系数小于 2^{32-D}。
pub fn Poly::shiftl(self : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = self.coeffs[i] << D
  }
}

///| Inplace forward NTT. Output coefficients can be up to
/// 16*Q larger than input coefficients.
/// 原地正向 NTT。输出系数可能比输入系数大至多 16*Q。
pub fn Poly::ntt(self : Poly) -> Unit {
  ntt(self.coeffs)
}

///| Inplace inverse NTT and multiplication by 2^{32}.
/// Input coefficients need to be less than 2*Q.
/// Output coefficients are less than 2*Q.
/// 原地逆向 NTT 并乘以 2^{32}。
/// 输入系数需要小于 2*Q。
/// 输出系数小于 2*Q。
pub fn Poly::inv_ntt_to_mont(self : Poly) -> Unit {
  inv_ntt_to_mont(self.coeffs)
}

///| Pointwise multiplication of polynomials in NTT domain
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

///| For all coefficients c of the input polynomial,
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

///| For all coefficients c of the input polynomial,
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

///| Compute hint polynomial. The coefficients of which indicate
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

///| Use hint polynomial to correct the high bits of a polynomial.
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

///| Check infinity norm of polynomial against given bound.
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

///| Sample uniformly random coefficients in [0, Q-1] by
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
  a : ArrayView[Int],
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
      a[cnt] = t.reinterpret_as_int()
      cnt = cnt + 1
    }
  }
  cnt
}

///|
pub const POLY_UNIFORM_NBLOCKS : UInt = (768 + STREAM128_BLOCKBYTES - 1) /
  STREAM128_BLOCKBYTES

///|
pub fn Poly::uniform(self : Poly, seed : Array[Byte], nonce : UInt16) -> Unit {
  let mut buflen = (POLY_UNIFORM_NBLOCKS * STREAM128_BLOCKBYTES).reinterpret_as_int()
  let buf : Array[Byte] = Array::make(buflen + 2, 0)
  let state = KeccakState::default()
  stream128_init(state, seed, nonce)
  stream128_squeezeblocks(buf, POLY_UNIFORM_NBLOCKS.to_uint64(), state)
  let mut cnt = rej_uniform(self.coeffs, N, buf, buflen)
  let mut off = 0
  while cnt.reinterpret_as_uint() < N.reinterpret_as_uint() {
    off = buflen % 3
    for i in 0..<off {
      buf[i] = buf[buflen - off + i]
    }
    buflen = STREAM128_BLOCKBYTES.reinterpret_as_int() + off
    stream128_squeezeblocks(buf[off:], 1, state)
    cnt = cnt + rej_uniform(self.coeffs[cnt:], N - cnt, buf, buflen)
  }
}

///|
pub fn rej_eta(
  a : ArrayView[Int],
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
        a[cnt] = 2 - t0.reinterpret_as_int()
        cnt += 1
      }
      if t1 < 15 && cnt < len {
        t1 = t1 - ((205 * t1) >> 10) * 5
        a[cnt] = 2 - t1.reinterpret_as_int()
        cnt = cnt + 1
      }
    } else if eta == 4 {
      if t0 < 9 {
        a[cnt] = 4 - t0.reinterpret_as_int()
        cnt = cnt + 1
      }
      if t1 < 9 && cnt < len {
        a[cnt] = 4 - t1.reinterpret_as_int()
        cnt = cnt + 1
      }
    }
  }
  cnt.reinterpret_as_uint()
}

///|
pub fn poly_uniform_eta(
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
  let mut cnt = rej_eta(self.coeffs, N, buf, buflen)
  while cnt < N.reinterpret_as_uint() {
    stream256_squeezeblocks(buf, 1, state)
    cnt += rej_eta(
      self.coeffs[cnt.reinterpret_as_int():],
      N - cnt.reinterpret_as_int(),
      buf,
      STREAM256_BLOCKBYTES.reinterpret_as_int(),
    )
  }
}

///| Sample polynomial with uniformly random coefficients
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

///| Implementation of H. Samples polynomial with TAU nonzero
/// coefficients in {-1,1} using the output stream of
/// SHAKE256(seed).
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

///| Bit-pack polynomial with coefficients in [-ETA,ETA].
/// Input coefficients are assumed to lie in [Q-ETA,Q+ETA].
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

///| Unpack polynomial with coefficients in [-ETA,ETA].
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

///| Bit-pack polynomial t1 with coefficients fitting in 10 bits.
/// Input coefficients are assumed to be standard representatives.
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

///| Unpack polynomial t1 with 9-bit coefficients.
/// Output coefficients are standard representatives.
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

///| Bit-pack polynomial t0 with coefficients in [-2^{D-1}, 2^{D-1}].
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

///| Unpack polynomial t0 with coefficients in ]-2^{D-1}, 2^{D-1}].
/// Output coefficients lie in ]Q-2^{D-1},Q+2^{D-1}].
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

///| Bit-pack polynomial z with coefficients
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

///| Unpack polynomial z with coefficients
/// in [-(GAMMA1 - 1), GAMMA1 - 1].
/// Output coefficients are standard representatives.
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

///| Bit-pack polynomial w1 with coefficients in [0, 15].
/// Input coefficients are assumed to be standard representatives.
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
