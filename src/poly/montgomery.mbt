// 蒙哥马利模乘，快速计算 c = a * b % Q 
// R = 2 ^ 32
// 蒙哥马利约减, reduce(a) = a / R % Q, 将 a 从蒙哥马利域转换到普通域
// 蒙哥马利乘法, mul(a, b) = a * b / R = reduce(a * b) 
// a * R % Q, 将 a 从普通域转换到蒙哥马利域

///|
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
  let t = (a + (1 << 22)) >> 23 // 近似 a / Q 
  let t = a - t * Q
  t
}

///| 如果输入为负数，则加上Q
pub fn caddq(a : Int) -> Int {
  a + ((a >> 31) & Q) // a是负数时算术右移31位得到全1
}

///|
test "caddq" {
  inspect!(caddq(-10), content="\{Q - 10}")
  inspect!(caddq(-1), content="\{Q - 1}")
  inspect!(caddq(0), content="0")
  inspect!(caddq(1), content="1")
}
