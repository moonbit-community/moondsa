///|
/// Montgomery modular arithmetic for efficient computation in Z_q.
///
/// This module implements Montgomery modular multiplication and reduction
/// techniques for efficient arithmetic in the finite field Z_q where q = 8380417.
/// Montgomery arithmetic provides significant performance improvements for
/// modular operations by avoiding expensive division operations.
///
/// # Montgomery Domain
///
/// The Montgomery representation maps integers a to aR mod q where R = 2^32.
/// This allows efficient modular multiplication using only shifts and additions.
///
/// # Implementation Details
///
/// - QINV: Modular inverse of q modulo R, satisfying QINV * q ≡ 1 (mod R)
/// - All operations use 64-bit intermediate results to prevent overflow
/// - Constant-time implementation to prevent timing attacks
///
/// # References
///
/// - Montgomery, P. L. "Modular multiplication without trial division" (1985)
/// - NIST FIPS 204: Module-Lattice-Based Digital Signature Standard

///|
/// Modular inverse of Q modulo 2^32, used in Montgomery reduction.
///
/// This constant satisfies the equation: QINV * Q ≡ 1 (mod 2^32)
/// where Q = 8380417. Used for efficient Montgomery modular reduction.
const QINV : Int = 58728449 // QINV * Q % R = 1

///| 将 a 从蒙哥马利域转换到普通域
/// return a * R^-1 % Q
/// 
pub fn montgomery_reduce(a : Int64) -> Int {
  let t : Int64 = (a.to_int() * QINV).to_int64()
  let x = (a - t * Q.to_int64()) >> 32
  x.to_int()
}

///| 对于一个有限域元素a, a <= 2 ^ {31} - 2 ^ {22} - 1,
/// 计算 r \equiv a (mod Q), 满足 -6283009 <= r <= 6283008
pub fn reduce32(a : Int) -> Int {
  /// Q = 8380417, 2 ^ {22} = 4194304, 2 ^ {23} = 8388608
  let mut t = (a + (1 << 22)) >> 23 // 近似 a / Q 
  t = a - t * Q
  t
}

///| 如果输入为负数，则加上Q
pub fn caddq(a : Int) -> Int {
  a + ((a >> 31) & Q) // a是负数时算术右移31位得到全1
}

///|
test "caddq" {
  inspect(caddq(-10), content="\{Q - 10}")
  inspect(caddq(-1), content="\{Q - 1}")
  inspect(caddq(0), content="0")
  inspect(caddq(1), content="1")
}
