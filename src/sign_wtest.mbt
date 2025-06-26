///|
fn hex_char_to_int(c : Char) -> Int {
  match c {
    '0'..='9' => c.to_int() - '0'.to_int()
    'a'..='f' => c.to_int() - 'a'.to_int() + 10
    'A'..='F' => c.to_int() - 'A'.to_int() + 10
    _ => 0
  }
}

///|
fn int_to_hex_char(n : Int) -> String {
  match n {
    0..=9 => (n + '0'.to_int()).unsafe_to_char().to_string()
    10..=15 => (n - 10 + 'A'.to_int()).unsafe_to_char().to_string()
    _ => ""
  }
}

///|
fn hex_str_to_bytes(str : String) -> Array[Byte] {
  let bytes : Array[Byte] = Array::new()
  let chars = str.to_array()
  for i in 0..<(chars.length() / 2) {
    let byte : Byte = (hex_char_to_int(chars[i * 2]) * 16 +
    hex_char_to_int(chars[i * 2 + 1])).to_byte()
    bytes.push(byte)
  }
  bytes
}

///|
fn print_bytes(bytes : Array[Byte]) -> Unit {
  let mut str = ""
  for i in 0..<bytes.length() {
    let hex = bytes[i].to_int()
    str += int_to_hex_char(hex >> 4)
    str += int_to_hex_char(hex & 0x0F)
  }
  println(str)
}

///|
test "kat-Dilithium5" {
  dilithium_context.set_level(SecurityLevel::Dilithium5)
  let seed = hex_str_to_bytes(
    "061550234D158C5EC95595FE04EF7A25767F2E24CC2BC479D09D86DC9ABCFDE7056A8C266F9EF97ED08541DBD2E1FFA1",
  )
  print_bytes(seed)
  let (pk, sk) = crypto_sign_keypair(Ok(seed))
  println("pk: ")
  print_bytes(pk)
  println("sk: ")
  print_bytes(sk)
}
