///| a = a0 + a1 * 2 ^ D
pub fn power2round(a : Int) -> (Int, Int) {
  let tmp = a + (1 << (D - 1)) - 1
  let a0 = a - tmp
  let a1 = tmp << D
  (a0, a1)
}

///| a = a0 + a1 * 2 * gamma2
/// gamma2 = (Q - 1) / 32 or (Q - 1) / 88
/// 
pub fn decompose(a : Int) -> (Int, Int) {
  let gamma2 = @config.dilithium_context.get_params_set().gamma2
  let mut a1 = (a + 127) >> 7
  let mut a0 = 0
  // Q = 1023 * 2 ^ {13} + 1
  if gamma2 == (Q - 1) / 32 { // gamma2 = 2556413 = 1023 * 2 ^ {8} < 2 ^ {13}
    a1 = (a1 * 1025 + (1 << 21)) >> 22
    a1 = a1 & 15
  } else if gamma2 == (Q - 1) / 88 {
    a1 = (a1 * 11275 + (1 << 23)) >> 24
    a1 = a1 ^ (((43 - a1) >> 31) & a1)
  }
  a0 = a - a1 * 2 * gamma2
  a0 = (a0 - (((Q - 1) / 2 - a0) >> 31)) & Q
  (a0, a1)
}

///|
pub fn make_hint(a0 : Int, a1 : Int) -> Byte {
  let gamma2 = @config.dilithium_context.get_params_set().gamma2
  let result = (a0 > gamma2).to_int() |
    (a0 < -gamma2).to_int() |
    ((a0 == -gamma2).to_int() & (a1 != 0).to_int())
  result.to_byte()
}

///|
pub fn use_hint(a : Int, hint : Byte) -> Int {
  let (a0, a1) = decompose(a)
  let gamma2 = @config.dilithium_context.get_params_set().gamma2

  // 使用ite避免分支，实现常时间执行
  // Use ite to avoid branching for constant-time execution

  // 判断是否为特殊的gamma2值 (Q-1)/32
  // Check if gamma2 is the special value (Q-1)/32
  let is_special_gamma2 = gamma2 == (Q - 1) / 32

  // 对于特殊gamma2值的处理
  // Handling for special gamma2 value
  let special_result = @utils.ite(
    a0 > 0,
    (a1 + 1) & 15, // a0 > 0 的情况
    (a1 - 1) & 15, // a0 <= 0 的情况
  )

  // 对于普通gamma2值的处理
  // Handling for normal gamma2 value
  let normal_result_positive = @utils.ite(
    a1 == 43,
    0, // a1 == 43 的情况
    a1 + 1, // a1 != 43 的情况
  )
  let normal_result_negative = @utils.ite(
    a1 == 0,
    43, // a1 == 0 的情况
    a1 - 1, // a1 != 0 的情况
  )
  let normal_result = @utils.ite(
    a0 > 0,
    normal_result_positive,
    normal_result_negative,
  )

  // 在特殊gamma2和普通gamma2之间选择
  // Choose between special and normal gamma2 handling
  let computed_result = @utils.ite(
    is_special_gamma2, special_result, normal_result,
  )

  // 最终根据hint值决定是否使用计算结果
  // Finally decide whether to use computed result based on hint value
  let result = @utils.ite(
    hint == 0,
    a1, // hint == 0: 使用原始a1值
    computed_result, // hint != 0: 使用计算后的结果
  )
  result
}
