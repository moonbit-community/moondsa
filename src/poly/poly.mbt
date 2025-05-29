///| Polynomial degree / 多项式次数
const N : Int = @config.N

///| Rounding parameter D for decomposition / 分解用的舍入参数 D
const D : Int = @config.D

///| D_SHL = 2^{D-1}, used for power-of-2 rounding / D_SHL = 2^{D-1}，用于2的幂次舍入
const D_SHL : Int = 1 << (D - 1)

///| Polynomial structure containing an array of coefficients.
/// 包含系数数组的多项式结构。
pub struct Poly {
  coeffs : Array[Int] // Coefficient array / 系数数组
}

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
pub fn Poly::pointwise_montgomery(self : Poly, other : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = montgomery_reduce(
      self.coeffs[i].to_int64() * other.coeffs[i].to_int64(),
    )
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
pub fn Poly::decompose(self : Poly, other : Poly) -> Unit {
  for i in 0..<N {
    let (a0, a1) = decompose(self.coeffs[i])
    self.coeffs[i] = a1
    other.coeffs[i] = a0
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
pub fn poly_chknorm(self : Poly, b : Int) -> Byte {
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
    t = coeff - (t & (2 * (coeff - 1)))
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
  buflen : Int
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
let poly_uniform_nblocks : UInt = (768 + @config.STREAM128_BLOCKBYTES - 1) /
  @config.STREAM128_BLOCKBYTES

///|
pub fn Poly::uniform(self : Poly, seed : Array[Byte], nonce : UInt16) -> Unit {
  let mut buflen = (poly_uniform_nblocks * @config.STREAM128_BLOCKBYTES).reinterpret_as_int()
  let buf : Array[Byte] = Array::make(buflen + 2, 0)
  let state = @hash.KeccakState::default()
  @hash.stream128_init(state, seed, nonce)
  @hash.stream128_squeezeblocks(buf, poly_uniform_nblocks.to_uint64(), state)
  let mut cnt = rej_uniform(self.coeffs, N, buf, buflen)
  let mut off = 0
  while cnt < N {
    off = buflen % 3
    for i in 0..<off {
      buf[i] = buf[buflen - off + i]
    }
    buflen = @config.STREAM128_BLOCKBYTES.reinterpret_as_int() + off
    @hash.stream128_squeezeblocks(buf[off:], 1, state)
    cnt = cnt + rej_uniform(self.coeffs[cnt:], N - cnt, buf, buflen)
  }
}

///|
pub fn rej_eta(
  a : ArrayView[Int],
  len : Int,
  buf : Array[Byte],
  buflen : Int
) -> Int {
  let mut cnt = 0
  let mut pos = 0
  let mut t0 = 0U
  let mut t1 = 0U
  let eta = @config.dilithium_context.get_params_set().eta
  while cnt < len && pos < buflen {
    t0 = (buf[pos] & 0x0F).to_uint()
    t1 = (buf[pos] >> 4).to_uint()
    pos = pos + 1
    if eta == 2 {
      if t0 < 15 {
        t0 = t0 - ((205 * t0) >> 10) * 5
        a[cnt] = 2 - t0.reinterpret_as_int()
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
  cnt
}

///|
let poly_uniform_eta_nblocks : UInt = if @config.dilithium_context.get_params_set().eta ==
  2 {
  (768 + @config.STREAM256_BLOCKBYTES - 1) / @config.STREAM256_BLOCKBYTES
} else {
  (1536 + @config.STREAM256_BLOCKBYTES - 1) / @config.STREAM256_BLOCKBYTES
}

///|
pub fn poly_uniform_eta(
  self : Poly,
  seed : Array[Byte],
  nonce : UInt16
) -> Unit {
  let buflen = (poly_uniform_eta_nblocks * @config.STREAM256_BLOCKBYTES).reinterpret_as_int()
  let buf : Array[Byte] = Array::make(buflen, 0)
  let state = @hash.KeccakState::default()
  @hash.stream256_init(state, seed, nonce)
  @hash.stream256_squeezeblocks(
    buf,
    poly_uniform_eta_nblocks.to_uint64(),
    state,
  )
  let mut cnt = rej_eta(self.coeffs, N, buf, buflen)
  while cnt < N {
    @hash.stream256_squeezeblocks(buf, 1, state)
    cnt = cnt +
      rej_eta(
        self.coeffs[cnt:],
        N - cnt,
        buf,
        @config.STREAM256_BLOCKBYTES.reinterpret_as_int(),
      )
  }
}
