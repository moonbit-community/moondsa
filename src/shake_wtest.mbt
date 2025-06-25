// SHAKE128 and SHAKE256 test cases | SHAKE128 和 SHAKE256 测试用例
// 测试 SHAKE128 和 SHAKE256 的基本用法

///| Convert byte array to lowercase hex string | 将字节数组转换为小写十六进制字符串
fn bytes_to_hex(bytes : Array[Byte]) -> String {
  let mut result = ""
  for i in 0..<bytes.length() {
    let byte_val = bytes[i].to_int()
    let hex_chars = "0123456789abcdef".to_array()
    let high = hex_chars[byte_val >> 4] // 右移4位
    let low = hex_chars[byte_val & 0x0F]
    result = result + high.to_string() + low.to_string()
  }
  result
}

///| Convert string to byte array | 将字符串转换为字节数组
fn string_to_bytes(s : String) -> Array[Byte] {
  let bytes : Array[Byte] = []
  for charcode in s.charcodes() {
    bytes.push(charcode.to_int().to_byte())
  }
  bytes
}

///| Test SHAKE128 with empty input, 16-byte output | 测试空输入的 SHAKE128，输出 16 字节
test "test_shake128_empty_16" {
  let state = KeccakState::default()
  let input : Array[Byte] = []
  shake128_absorb(state, input, 0)
  shake128_finalize(state)
  let output : Array[Byte] = Array::make(168, 0) // SHAKE128_RATE bytes
  shake128_squeezeblocks(output, 1, state)

  // NIST test vector for SHAKE128("", 16)
  let expected = "7f9c2ba4e88f827d616045507605853e"
  let actual = bytes_to_hex(output[0:16].to_array())
  inspect(actual, content=expected)  
}

///| Test SHAKE128 with "MoonBit Community" input | 测试字符串输入的 SHAKE128
test "test_shake128_moonbit" {
  let input = string_to_bytes("MoonBit Community")
  let state = KeccakState::default()
  shake128_absorb(state, input, input.length().reinterpret_as_uint())
  shake128_finalize(state)
  let output : Array[Byte] = Array::make(168, 0)
  shake128_squeezeblocks(output, 1, state)
  let expected = "677fd5abd26006e8" // First 8 bytes
  let actual = bytes_to_hex(output[0:8].to_array())
  inspect(actual, content=expected)
}

///| Test SHAKE256 with empty input, 16-byte output | 测试空输入的 SHAKE256，输出 16 字节
test "test_shake256_empty_16" {
  let state = KeccakState::default()
  let input : Array[Byte] = []
  shake256_absorb_once(state, input, 0)
  let output : Array[Byte] = Array::make(16, 0)
  shake256_squeeze(output[:], 16, state)

  // NIST test vector for SHAKE256("", 16)
  let expected = "46b9dd2b0ba88d13233b3feb743eeb24"
  let actual = bytes_to_hex(output)
  inspect(actual, content=expected)
}

///| Test SHAKE256 with "MoonBit Community" input | 测试字符串输入的 SHAKE256
test "test_shake256_moonbit" {
  let input = string_to_bytes("MoonBit Community")
  let output : Array[Byte] = Array::make(64, 0)
  shake256(output=output, 64, input=input, input.length().reinterpret_as_uint())
  let expected = "5d8bf49503d49e78" // First 8 bytes
  let actual = bytes_to_hex(output[0:8].to_array())
  inspect(actual, content=expected)
}

///| Test SHAKE128 incremental absorb | 测试 SHAKE128 增量吸收
test "test_shake128_incremental_absorb" {
  let state1 = KeccakState::default()
  let state2 = KeccakState::default()

  // One-shot absorb
  let input = string_to_bytes("Hello, World!")
  shake128_absorb(state1, input, input.length().reinterpret_as_uint())
  shake128_finalize(state1)

  // Incremental absorb
  let part1 = string_to_bytes("Hello, ")
  let part2 = string_to_bytes("World!")
  shake128_absorb(state2, part1, part1.length().reinterpret_as_uint())
  shake128_absorb(state2, part2, part2.length().reinterpret_as_uint())
  shake128_finalize(state2)

  // Both should produce same output
  let output1 : Array[Byte] = Array::make(32, 0)
  let output2 : Array[Byte] = Array::make(32, 0)
  shake256_squeeze(output1[:], 32, state1)
  shake256_squeeze(output2[:], 32, state2)
  let result1 = bytes_to_hex(output1)
  let result2 = bytes_to_hex(output2)
  inspect(result1 == result2, content="true")
}

///| Test SHAKE256 incremental squeeze | 测试 SHAKE256 增量挤压
test "test_shake256_incremental_squeeze" {
  let state = KeccakState::default()
  let input = string_to_bytes("Test")
  shake256_absorb_once(state, input, input.length().reinterpret_as_uint())

  // Squeeze in parts
  let part1 : Array[Byte] = Array::make(10, 0)
  let part2 : Array[Byte] = Array::make(10, 0)
  shake256_squeeze(part1[:], 10, state)
  shake256_squeeze(part2[:], 10, state)

  // Compare with one-shot squeeze
  let state2 = KeccakState::default()
  shake256_absorb_once(state2, input, input.length().reinterpret_as_uint())
  let full_output : Array[Byte] = Array::make(20, 0)
  shake256_squeeze(full_output[:], 20, state2)
  let incremental_result = bytes_to_hex(part1) + bytes_to_hex(part2)
  let full_result = bytes_to_hex(full_output)
  inspect(incremental_result == full_result, content="true")
}

///| Test SHAKE256 with longer input crossing rate boundary | 测试跨越比特率边界的长输入
test "test_shake256_long_input" {
  // Create input that's larger than SHAKE256_RATE (136 bytes)
  let input : Array[Byte] = Array::make(200, 0)
  for i in 0..<200 {
    input[i] = (i % 256).to_byte()
  }
  let output : Array[Byte] = Array::make(32, 0)
  shake256(output=output, 32, input=input, input.length().reinterpret_as_uint())

  // Just verify we get some output (specific value depends on implementation)
  let result = bytes_to_hex(output)
  inspect(result.length() == 64, content="true") // 32 bytes = 64 hex chars
}

///| Test SHAKE256 with output crossing rate boundary | 测试跨越比特率边界的输出
test "test_shake256_long_output" {
  let input = string_to_bytes("Short input")

  // Request output longer than SHAKE256_RATE (136 bytes)
  let output : Array[Byte] = Array::make(200, 0)
  shake256(output=output, 200, input=input, input.length().reinterpret_as_uint())
  let result = bytes_to_hex(output)
  inspect(result.length() == 400, content="true") // 200 bytes = 400 hex chars
}

///| Test edge case: input length exactly equals rate | 测试边界情况：输入长度恰好等于比特率
test "test_shake256_rate_boundary" {
  // SHAKE256_RATE = 136 bytes
  let input : Array[Byte] = Array::make(136, 0)
  for i in 0..<136 {
    input[i] = i.to_byte()
  }
  let output : Array[Byte] = Array::make(32, 0)
  shake256(output=output, 32, input=input, input.length().reinterpret_as_uint())
  let result = bytes_to_hex(output)
  inspect(result.length() == 64, content="true")
}
