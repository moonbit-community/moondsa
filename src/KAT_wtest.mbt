///|
/// test the Dilithium by KAT files
priv struct KAT {
  id : Int
  seed : Array[Byte]
  mlen : Int // message length
  msg : Array[Byte]
  pk : Array[Byte]
  sk : Array[Byte]
  smlen : Int // signature length
  sm : Array[Byte] // signature
}

///|
fn string_view_to_bytes(s : @string.View) -> Array[Byte] {
  let bytes : Array[Byte] = Array::new()
  let char_length = s.char_length()
  if (char_length & 1) != 0 {
    abort("String length must be even for hex conversion")
  }
  for i in 0..<(char_length / 2) {
    let byte : Byte = (hex_char_to_int(s.get_char(i * 2).unwrap()) * 16 +
    hex_char_to_int(s.get_char(i * 2 + 1).unwrap())).to_byte()
    bytes.push(byte)
  }
  bytes
}

///|
fn load_seed() -> Array[Array[Byte]] {
  let file_path = "kat/SeedBuffer_Dilithium"
  let content = @fs.read_file_to_string(file_path) catch {
    err => abort(err.to_string())
  }
  content
  .split("\n")
  .to_array()
  .map(line => line.to_string())
  .map(hex_str_to_bytes)
}

///|
fn load_kat_file(level : SecurityLevel) -> Array[KAT] {
  let file_name = match level {
    SecurityLevel::Dilithium2 => "PQCsignKAT_Dilithium2.rsp"
    SecurityLevel::Dilithium3 => "PQCsignKAT_Dilithium3.rsp"
    SecurityLevel::Dilithium5 => "PQCsignKAT_Dilithium5.rsp"
  }
  let file_path = "kat/" + file_name
  let content = @fs.read_file_to_string(file_path) catch {
    err => abort(err.to_string())
  }
  fn extract_value_to_bytes(line : String) -> Array[Byte] {
    let value = line.split("=").last().unwrap().to_string()
    let bytes = string_view_to_bytes(value.trim_space())
    bytes
  }

  fn extract_value_to_int(line : String) -> Int {
    let value = line.split("=").last().unwrap().to_string()
    let int_value = try? @strconv.parse_int(value.trim_space().to_string())
    int_value.unwrap()
  }

  let lines = content
    .split("\n")
    .filter(line => not(line.is_empty()))
    .map(line => line.to_string())
  // count, seed, mlen, msg, pk, sk, smlen, sm
  let count = lines
    .filter(line => line.has_prefix("count"))
    .map(line => line.split("=").last().unwrap().to_string())
    .map(extract_value_to_int)
    .collect()
  let seed = lines
    .filter(line => line.has_prefix("seed"))
    .map(extract_value_to_bytes)
    .collect()
  let mlen = lines
    .filter(line => line.has_prefix("mlen"))
    .map(extract_value_to_int)
    .collect()
  let msg = lines
    .filter(line => line.has_prefix("msg"))
    .map(extract_value_to_bytes)
    .collect()
  let pk = lines
    .filter(line => line.has_prefix("pk"))
    .map(extract_value_to_bytes)
    .collect()
  let sk = lines
    .filter(line => line.has_prefix("sk"))
    .map(extract_value_to_bytes)
    .collect()
  let smlen = lines
    .filter(line => line.has_prefix("smlen"))
    .map(extract_value_to_int)
    .collect()
  let sm = lines
    .filter(line => line.has_prefix("sm "))
    .map(extract_value_to_bytes)
    .collect()
  let kats = []
  for i in 0..<count.length() {
    let kat = {
      id: count[i],
      seed: seed[i],
      mlen: mlen[i],
      msg: msg[i],
      pk: pk[i],
      sk: sk[i],
      smlen: smlen[i],
      sm: sm[i],
    }
    kats.push(kat)
  }
  return kats
}

///|
test "load_kat" {
  let _ = load_kat_file(SecurityLevel::Dilithium2)

}

///|
test "kat-keypair" {
  let seed_buffers = load_seed()
  let kats = load_kat_file(SecurityLevel::Dilithium2) // Adjust the security level as needed
  dilithium_context.set_level(SecurityLevel::Dilithium2)
  println("kats length: \{kats.length()}")
  for i in 0..<kats.length() {
    let kat = kats[i]
    let pk = kat.pk
    let sk = kat.sk
    let (pk2, sk2) = keypair_gen(Ok(seed_buffers[i]))
    inspect(pk2, content=pk.to_string())
    inspect(sk2, content=sk.to_string())
  }
  println("KeyPair Test Level 2: passed")
  let kats = load_kat_file(SecurityLevel::Dilithium3) // Adjust the security level as needed
  dilithium_context.set_level(SecurityLevel::Dilithium3)
  for i in 0..<kats.length() {
    let kat = kats[i]
    let pk = kat.pk
    let sk = kat.sk
    let (pk2, sk2) = keypair_gen(Ok(seed_buffers[i]))
    inspect(pk2, content=pk.to_string())
    inspect(sk2, content=sk.to_string())
  }
  println("KeyPair Test Level 3: passed")
  let kats = load_kat_file(SecurityLevel::Dilithium5) // Adjust the security level as needed
  dilithium_context.set_level(SecurityLevel::Dilithium5)
  for i in 0..<kats.length() {
    let kat = kats[i]
    let pk = kat.pk
    let sk = kat.sk
    let (pk2, sk2) = keypair_gen(Ok(seed_buffers[i]))
    inspect(pk2, content=pk.to_string())
    inspect(sk2, content=sk.to_string())
  }
  println("KeyPair Test Level 5: passed")
}

// #[test]
// pub fn sign() {
//   let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//   let filename = format!("PQCsignKAT_Dilithium{}{}.rsp", MODE, AES);
//   let katvec = kats(&mut path, &filename);
//   let mut cnt = 0;
//   for kat in katvec {
//     let sm = kat.sm.clone();
//     let msg = kat.msg.clone();
//     let sk = kat.sk.clone();
//     let mut sig = vec![0u8; SIGNBYTES];
//     crypto_sign_signature(&mut sig, &msg, &sk);
//     assert_eq!(sm[..SIGNBYTES], sig);
//     cnt += 1;
//   }
// }

///|
test "kat-sign" {
  let kats = load_kat_file(SecurityLevel::Dilithium2)
  dilithium_context.set_level(SecurityLevel::Dilithium2)
  let sign_bytes = dilithium_context.params_set.sign_bytes
  for i in 0..<kats.length() {
    let kat = kats[i]
    let msg = kat.msg
    let sk = kat.sk
    let sig = sign(msg, sk)
    let sm = kat.sm[:sign_bytes].to_array()
    inspect(sig, content=sm.to_string())
  }
  println("Sign Test Level 2: passed")
  let kats = load_kat_file(SecurityLevel::Dilithium3)
  dilithium_context.set_level(SecurityLevel::Dilithium3)
  let sign_bytes = dilithium_context.params_set.sign_bytes
  for i in 0..<kats.length() {
    let kat = kats[i]
    let msg = kat.msg
    let sk = kat.sk
    let sig = sign(msg, sk)
    let sm = kat.sm[:sign_bytes].to_array()
    inspect(sig, content=sm.to_string())
  }
  println("Sign Test Level 3: passed")
  let kats = load_kat_file(SecurityLevel::Dilithium5)
  dilithium_context.set_level(SecurityLevel::Dilithium5)
  let sign_bytes = dilithium_context.params_set.sign_bytes
  for i in 0..<kats.length() {
    let kat = kats[i]
    let msg = kat.msg
    let sk = kat.sk
    let sig = sign(msg, sk)
    let sm = kat.sm[:sign_bytes].to_array()
    inspect(sig, content=sm.to_string())
  }
  println("Sign Test Level 5: passed")
}

// #[test]
// pub fn verify() {
//   let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
//   let filename = format!("PQCsignKAT_Dilithium{}{}.rsp", MODE, AES);
//   let katvec = kats(&mut path, &filename);
//   for kat in katvec {
//     let sm = kat.sm.clone();
//     let msg = kat.msg.clone();
//     let pk = kat.pk.clone();
//     let res = crypto_sign_verify(&sm[..SIGNBYTES], &msg, &pk);
//     assert!(res.is_ok());
//   }
// }

///|
test "kat-verify" {
  let kats = load_kat_file(SecurityLevel::Dilithium2)
  dilithium_context.set_level(SecurityLevel::Dilithium2)
  let sign_bytes = dilithium_context.params_set.sign_bytes
  for i in 0..<kats.length() {
    let kat = kats[i]
    let sm = kat.sm[:sign_bytes].to_array()
    let msg = kat.msg
    let pk = kat.pk
    let res = verify(sm, msg, pk)
    res.unwrap() // Ensure the verification is successful
  }
  println("Verify Test Level 2: passed")
  let kats = load_kat_file(SecurityLevel::Dilithium3)
  dilithium_context.set_level(SecurityLevel::Dilithium3)
  let sign_bytes = dilithium_context.params_set.sign_bytes
  for i in 0..<kats.length() {
    let kat = kats[i]
    let sm = kat.sm[:sign_bytes].to_array()
    let msg = kat.msg
    let pk = kat.pk
    let res = verify(sm, msg, pk)
    res.unwrap() // Ensure the verification is successful
  }
  println("Verify Test Level 3: passed")
  let kats = load_kat_file(SecurityLevel::Dilithium5)
  dilithium_context.set_level(SecurityLevel::Dilithium5)
  let sign_bytes = dilithium_context.params_set.sign_bytes
  for i in 0..<kats.length() {
    let kat = kats[i]
    let sm = kat.sm[:sign_bytes].to_array()
    let msg = kat.msg
    let pk = kat.pk
    let res = verify(sm, msg, pk)
    res.unwrap() // Ensure the verification is successful
  }
  println("Verify Test Level 5: passed")
}
