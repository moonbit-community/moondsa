///|这里主要定义了一些外部api,同时为将来支持aes做准备
pub const SEEDBYTES : UInt = 32

///|
pub const CRHBYTES : UInt = 64

///|
pub fn stream128_init(
  state : KeccakState,
  seed : Array[Byte],
  nonce : UInt16
) -> Unit {
  dilithium_shake128_stream_init(state, seed, nonce)
}

///|
pub fn stream128_squeezeblocks(
  out : ArrayView[Byte],
  outblocks : UInt64,
  state : KeccakState
) -> Unit {
  shake128_squeezeblocks(out, outblocks.to_uint(), state)
}

///|
pub fn dilithium_shake128_stream_init(
  state : KeccakState,
  seed : Array[Byte],
  nonce : UInt16
) -> Unit {
  let t = [nonce.to_byte(), (nonce >> 8).to_byte()]
  state.init()
  shake128_absorb(state, seed, SEEDBYTES)
  shake128_absorb(state, t, 2)
  shake128_finalize(state)
}

///|
pub fn stream256_init(
  state : KeccakState,
  seed : Array[Byte],
  nonce : UInt16
) -> Unit {
  dilithium_shake256_stream_init(state, seed, nonce)
}

///|
pub fn stream256_squeezeblocks(
  out : Array[Byte],
  outblocks : UInt64,
  state : KeccakState
) -> Unit {
  shake256_squeezeblocks(out, outblocks.to_uint(), state)
}

///|
pub fn dilithium_shake256_stream_init(
  state : KeccakState,
  seed : Array[Byte],
  nonce : UInt16
) -> Unit {
  let t = [nonce.to_byte(), (nonce >> 8).to_byte()]
  state.init()
  shake256_absorb(state, seed, SEEDBYTES)
  shake256_absorb(state, t, 2)
  shake256_finalize(state)
}
