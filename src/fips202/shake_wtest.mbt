// 测试 SHAKE128 和 SHAKE256 的基本用法

///| 测试: SHAKE128 对空输入，输出前 16 字节是否符合预期
test "test_shake128_empty_16" {
  // 1. 初始化状态
  let state = KeccakState::default()
  // 2. 吸收空输入
  let input : Array[Byte] = Array::make(512, 0)
  shake128_absorb(state, input, 0)
  // 3. 结束吸收阶段
  shake128_finalize(state)
  // 4. 挤出 512 字节输出
  let output : Array[Byte] = Array::make(512, 0)
  shake128_squeezeblocks(output, 1, state)
  // 5. 验证输出
  // 参考 NIST SHAKE128("", 16) 前 16 字节：7f 9c 2b a4 e8 8f 82 7d 61 60 45 50 76 05 85 3e
  let expected : Array[Byte] = Array::make(16, 0)
  expected[0] = 0x7FUL.to_byte()
  expected[1] = 0x9cUL.to_byte()
  expected[2] = 0x2bUL.to_byte()
  expected[3] = 0xa4UL.to_byte()
  expected[4] = 0xe8UL.to_byte()
  expected[5] = 0x8fUL.to_byte()
  expected[6] = 0x82UL.to_byte()
  expected[7] = 0x7dUL.to_byte()
  expected[8] = 0x61UL.to_byte()
  expected[9] = 0x60UL.to_byte()
  expected[10] = 0x45UL.to_byte()
  expected[11] = 0x50UL.to_byte()
  expected[12] = 0x76UL.to_byte()
  expected[13] = 0x05UL.to_byte()
  expected[14] = 0x85UL.to_byte()
  expected[15] = 0x3eUL.to_byte()
  let mut flag = true
  for i in 0..<16 {
    if output[i] != expected[i] {
      flag = false
      break
    }
  }
  inspect!(flag, content="true")
}

///| 测试: SHAKE256 对空输入，输出前 16 字节是否符合预期
test "test_shake256_empty_16" {
  // 1. 初始化并一次性吸收空输入
  let state = KeccakState::default()
  let input : Array[Byte] = Array::make(512, 0)
  shake256_absorb_once(state, input, 0)
  // 2. 挤出 16 字节输出
  let output : Array[Byte] = Array::make(512, 0)
  // 全部都是部分块，nblocks = 0
  shake256_squeezeblocks(output, 0, state)
  // 剩余不足一块的部分
  shake256_squeeze(output[:], 16, state)

  // 3. 验证输出
  // 参考 NIST SHAKE256("", 16) 前 16 字节：46 b9 dd 2b 0b a8 8d 13 23 3b 3f eb 74 3e eb 24
  let expected : Array[Byte] = Array::make(512, 0)
  expected[0] = 0x46UL.to_byte()
  expected[1] = 0xb9UL.to_byte()
  expected[2] = 0xddUL.to_byte()
  expected[3] = 0x2bUL.to_byte()
  expected[4] = 0x0bUL.to_byte()
  expected[5] = 0xa8UL.to_byte()
  expected[6] = 0x8dUL.to_byte()
  expected[7] = 0x13UL.to_byte()
  expected[8] = 0x23UL.to_byte()
  expected[9] = 0x3bUL.to_byte()
  expected[10] = 0x3fUL.to_byte()
  expected[11] = 0xebUL.to_byte()
  expected[12] = 0x74UL.to_byte()
  expected[13] = 0x3eUL.to_byte()
  expected[14] = 0xebUL.to_byte()
  expected[15] = 0x24UL.to_byte()
  let mut flag = true
  for i in 0..<16 {
    if output[i] != expected[i] {
      flag = false
      break
    }
  }
  inspect!(flag, content="true")
}
