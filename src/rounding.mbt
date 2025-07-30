///|
/// Rounding and decomposition operations for the Dilithium signature scheme.
///
/// This module implements specialized rounding and decomposition algorithms
/// required by the Dilithium signature scheme. These operations are crucial
/// for signature compression and the rejection sampling process that ensures
/// signature security.
///
/// # Mathematical Background
///
/// The rounding operations implement specific algorithms from the Dilithium
/// specification that enable:
/// - Efficient signature compression
/// - Constant-time implementation to prevent timing attacks
/// - Correct handling of modular arithmetic in Z_q
///
/// # Security Considerations
///
/// All operations are implemented to run in constant time to prevent
/// timing-based side-channel attacks. The decomposition functions use
/// bit manipulation techniques to avoid conditional branches.
///
/// # Examples
///
/// ```moonbit
/// // Power-of-2 rounding
/// let (a0, a1) = @ruifeng/moondsa.power2round(12345)
/// 
/// // Decomposition for signature compression
/// let (a0, a1) = @ruifeng/moondsa.decompose(98765)
/// 
/// // Hint generation for verification
/// let hint = @ruifeng/moondsa.make_hint(a0, a1)
/// ```

///|
/// Decomposes an integer `a` into two components `a0` and `a1` such that `a =
/// a0 + a1 * 2^D`, where `D` is a predefined constant.
///
/// This function implements the power-of-2 rounding operation commonly used in
/// lattice-based cryptography, particularly in the Dilithium digital signature
/// scheme. The decomposition ensures that `a0` is in the range `[-2^(D-1),
/// 2^(D-1))` and `a1` represents the higher-order bits.
///
/// Parameters:
///
/// * `a` : The integer value to be decomposed.
///
/// Returns a tuple `(a0, a1)` where `a0` is the low-order component and `a1` is
/// the high-order component such that `a = a0 + a1 * 2^D`.
pub fn power2round(a : Int) -> (Int, Int) {
  let a1 = (a + (1 << (D - 1)) - 1) >> D
  let a0 = a - (a1 << D)
  (a0, a1)
}

///|
/// Decomposes an integer into two components according to the Dilithium
/// signature scheme's decomposition algorithm.
///
/// This function implements the `Decompose` operation from the Dilithium
/// post-quantum cryptographic signature scheme. It splits an input integer `a`
/// into two parts `a0` and `a1` such that `a = a0 + a1 * 2 * gamma2`, where
/// `gamma2` is determined by the current Dilithium parameter set and can be
/// either `(Q-1)/32` or `(Q-1)/88`.
///
/// Parameters:
///
/// * `a` : The integer to be decomposed.
///
/// Returns a tuple `(a0, a1)` where `a0` is the low-order component and `a1` is
/// the high-order component of the decomposition.
pub fn decompose(a : Int) -> (Int, Int) {
  let gamma2 = dilithium_context.get_params_set().gamma2
  let mut a1 = (a + 127) >> 7
  let mut a0 = a
  // Q = 1023 * 2 ^ {13} + 1
  if gamma2 == (Q - 1) / 32 { // gamma2 = 2556413 = 1023 * 2 ^ {8} < 2 ^ {13}
    a1 = (a1 * 1025 + (1 << 21)) >> 22
    a1 = a1 & 15
  } else if gamma2 == (Q - 1) / 88 {
    a1 = (a1 * 11275 + (1 << 23)) >> 24
    a1 = a1 ^ (((43 - a1) >> 31) & a1)
  }
  a0 = a - a1 * 2 * gamma2
  a0 = a0 - ((((Q - 1) / 2 - a0) >> 31) & Q)
  (a0, a1)
}

///|
/// Generates a hint byte based on the decomposed polynomial coefficient
/// components for use in the Dilithium signature scheme.
///
/// Parameters:
///
/// * `a0` : The low-order component of the decomposed coefficient.
/// * `a1` : The high-order component of the decomposed coefficient.
///
/// Returns a hint byte (0 or 1) indicating whether the coefficient requires
/// adjustment during verification.
pub fn make_hint(a0 : Int, a1 : Int) -> Byte {
  let gamma2 = dilithium_context.get_params_set().gamma2
  let result = (a0 > gamma2).to_int() |
    (a0 < -gamma2).to_int() |
    ((a0 == -gamma2).to_int() & (a1 != 0).to_int())
  result.to_byte()
}

///|
/// Applies a hint to adjust the high-order bits of a polynomial coefficient in
/// the Dilithium signature scheme.
///
/// Parameters:
///
/// * `a` : The polynomial coefficient to be adjusted.
/// * `hint` : A hint byte that determines whether adjustment should be applied
///   (0 = no adjustment, non-zero = apply adjustment).
///
/// Returns the adjusted high-order bits `a1` after applying the hint-based
/// correction.
pub fn use_hint(a : Int, hint : Byte) -> Int {
  let (a0, a1) = decompose(a)
  let gamma2 = dilithium_context.get_params_set().gamma2

  // 使用ite避免分支，实现常时间执行
  // Use ite to avoid branching for constant-time execution

  // 判断是否为特殊的gamma2值 (Q-1)/32
  // Check if gamma2 is the special value (Q-1)/32
  let is_special_gamma2 = gamma2 == (Q - 1) / 32

  // 对于特殊gamma2值的处理
  // Handling for special gamma2 value
  let special_result = ite(
    a0 > 0,
    (a1 + 1) & 15, // a0 > 0 的情况
    (a1 - 1) & 15, // a0 <= 0 的情况
  )

  // 对于普通gamma2值的处理
  // Handling for normal gamma2 value
  let normal_result_positive = ite(
    a1 == 43,
    0, // a1 == 43 的情况
    a1 + 1, // a1 != 43 的情况
  )
  let normal_result_negative = ite(
    a1 == 0,
    43, // a1 == 0 的情况
    a1 - 1, // a1 != 0 的情况
  )
  let normal_result = ite(
    a0 > 0,
    normal_result_positive,
    normal_result_negative,
  )

  // 在特殊gamma2和普通gamma2之间选择
  // Choose between special and normal gamma2 handling
  let computed_result = ite(is_special_gamma2, special_result, normal_result)

  // 最终根据hint值决定是否使用计算结果
  // Finally decide whether to use computed result based on hint value
  let result = ite(
    hint == 0,
    a1, // hint == 0: 使用原始a1值
    computed_result, // hint != 0: 使用计算后的结果
  )
  result
}
