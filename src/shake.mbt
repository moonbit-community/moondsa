///|
/// SHAKE (Secure Hash Algorithm Keccak) extendable-output functions for Dilithium.
///
/// This module implements the SHAKE128 and SHAKE256 extendable-output functions (XOF)
/// based on the Keccak sponge construction. These functions serve as the primary
/// source of cryptographic randomness and hash operations within the Dilithium
/// signature scheme.
///
/// # Cryptographic Role
///
/// SHAKE functions are used throughout Dilithium for:
/// - Seed expansion during key generation
/// - Challenge polynomial generation during signing
/// - Random polynomial sampling
/// - Hash-based message processing
///
/// # Implementation Details
///
/// The implementation follows the NIST FIPS 202 standard specification and uses
/// the Keccak[1600] permutation with appropriate padding and domain separation.
///
/// # References
///
/// - NIST FIPS 202: SHA-3 Standard - Permutation-Based Hash and Extendable-Output Functions
/// - Keccak Team: https://keccak.team/
/// - Original reference: https://github.com/Argyle-Software/dilithium/blob/master/src/fips202.rs
///
/// # Keccak Algorithm Overview (Sponge Construction)
///
/// The Keccak algorithm operates as a sponge construction with three main phases:
///
/// 1. **Absorbing Phase**: Input data is absorbed into a fixed-size state.
///    Data is processed in blocks, with permutation applied after each block.
///
/// This file implements the SHAKE128 and SHAKE256 extendable-output functions
/// based on the Keccak algorithm, which forms the foundation of SHA-3.
/// 本文件基于 Keccak 算法实现 SHAKE128 和 SHAKE256 可扩展输出函数，
/// Keccak 算法是 SHA-3 的基础。
///
/// ## Keccak Algorithm Overview (Sponge Construction)
/// ## Keccak 算法概览（海绵结构）
/// 
/// The Keccak algorithm operates as a sponge construction with three main phases:
/// Keccak 算法采用海绵结构，包含三个主要阶段：
///
/// 1. **Absorbing Phase**: Input data is absorbed into a fixed-size state.
///    **吸收阶段**：输入数据被吸收到固定大小的状态中。
///    Data is processed in blocks, with permutation applied after each block.
///    数据以块为单位处理，每个块处理后都会进行一次置换。
///
/// 2. **Finalizing Phase**: Padding is added to mark the end of input.
///    **完成阶段**：添加填充以标记输入的结束。
///    This prepares the state for the squeezing phase.
///    这为挤压阶段准备状态。
///
/// 3. **Squeezing Phase**: Output data is squeezed from the state.
///    **挤压阶段**：从状态中挤压出输出数据。
///    Permutation is applied as needed to generate more output.
///    根据需要进行置换以生成更多输出。
///
/// SHAKE functions are XOFs, meaning they can produce output of any desired length.
/// SHAKE 函数是 XOF，意味着它们可以产生任意所需长度的输出。

///| SHAKE128 rate (block size) in bytes | SHAKE128 的比特率（块大小），以字节为单位
// pub const SHAKE128_RATE : UInt = 168

///| SHAKE256 rate (block size) in bytes | SHAKE256 的比特率（块大小），以字节为单位
// pub const SHAKE256_RATE : UInt = 136

///|
/// Defines the number of rounds in the Keccak-f\[1600] permutation function.
///
/// The Keccak-f\[1600] permutation is the core cryptographic primitive used in
/// the SHAKE128 and SHAKE256 extendable-output functions. This constant
/// specifies that exactly 24 rounds of transformation are applied to the
/// 1600-bit state during each permutation operation, which is essential for
/// achieving the required security properties of the Keccak algorithm.
const NROUNDS : Int = 24

///|
/// Internal state structure for Keccak cryptographic hash functions.
///
/// Fields:
///
/// * `s` : 25-element flattened representation of the 5x5 Keccak state matrix,
///   where each element is a 64-bit word.
/// * `pos` : Current byte position within the rate block, used to track
///   progress during incremental absorption and squeezing operations.
pub struct KeccakState {
  s : FixedArray[UInt64] // 25-element flattened state array | 25 元素的展平状态数组
  mut pos : UInt // Current position in the rate block | 当前在比特率块中的位置
} derive(Show)

///|
/// Creates a default instance of `KeccakState` with all state elements
/// initialized to zero.
///
/// Returns a new `KeccakState` with:
///
/// * `s`: A 25-element array of 64-bit unsigned integers, all initialized to 0
/// * `pos`: Current position set to 0
pub impl Default for KeccakState with default() {
  { s: FixedArray::make(25, 0), pos: 0 }
}

///|
/// Resets the Keccak state to its initial clean state with all fields zeroed.
///
/// Parameters:
///
/// * `self` : The KeccakState instance to be initialized.
pub fn KeccakState::init(self : KeccakState) -> Unit {
  self.s.fill(0)
  self.pos = 0
}

///|
/// Performs circular left rotation on a 64-bit unsigned integer by the
/// specified number of bit positions.
///
/// Parameters:
///
/// * `value` : The 64-bit unsigned integer to rotate.
/// * `positions` : The number of bit positions to rotate left. Should be
///   between 0 and 63 for meaningful results.
///
/// Returns the rotated 64-bit unsigned integer where bits that shift beyond the
/// left edge wrap around to the right edge.
fn KeccakState::rol(a : UInt64, offset : Int) -> UInt64 {
  (a << offset) | (a >> (64 - offset))
}

///|
/// Converts an 8-byte array into a 64-bit unsigned integer using little-endian
/// byte ordering.
///
/// Parameters:
///
/// * `x` : An array of 8 bytes to be converted to a 64-bit integer.
///
/// Returns a `UInt64` value constructed from the input bytes in little-endian
/// format.
pub fn load64(x : Array[Byte]) -> UInt64 {
  let mut r = 0UL
  for i in 0..<8 {
    let v : UInt64 = x[i].to_uint64() << (8 * i)
    r = r | v
  }
  r
}

///|
/// Stores a 64-bit unsigned integer into an 8-byte array using little-endian
/// byte order.
///
/// Parameters:
///
/// * `x` : The 8-byte array where the integer will be stored.
/// * `u` : The 64-bit unsigned integer to be stored.
pub fn store64(x : Array[Byte], u : UInt64) -> Unit {
  for i in 0..<8 {
    x[i] = (u >> (8 * i)).to_byte()
  }
}

///|
/// Precomputed round constants used in the Keccak-f\[1600] permutation
/// function.
///
/// This array contains the 24 round constants that are XORed with the state
/// during the iota step of each round in the Keccak-f\[1600] permutation. Each
/// constant is a 64-bit value that was derived from a linear feedback shift
/// register (LFSR) as specified in the Keccak specification. These constants
/// ensure that each round of the permutation is cryptographically distinct and
/// contribute to the security properties of the SHAKE128 and SHAKE256
/// functions.
///
/// The constants are applied in order during the 24 rounds of the Keccak
/// permutation, with `keccakf_round_constants[i]` being used in round `i`. The
/// values follow the official Keccak specification and are critical for the
/// correctness of the cryptographic hash function implementation.
///
let keccakf_round_constants : ReadOnlyArray[UInt64] = [
  0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
  0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
  0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
  0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
  0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
  0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
]

///|
/// Keccak-f[1600] permutation function | Keccak-f[1600] 置换函数
/// Applies the complete Keccak permutation to the state
/// 对状态应用完整的 Keccak 置换
pub fn keccakf1600_statepermute(state : FixedArray[UInt64]) -> Unit {
  // Copy state to local variables for processing | 将状态复制到局部变量进行处理
  let mut aba = state[0]
  let mut abe = state[1]
  let mut abi = state[2]
  let mut abo = state[3]
  let mut abu = state[4]
  let mut aga = state[5]
  let mut age = state[6]
  let mut agi = state[7]
  let mut ago = state[8]
  let mut agu = state[9]
  let mut aka = state[10]
  let mut ake = state[11]
  let mut aki = state[12]
  let mut ako = state[13]
  let mut aku = state[14]
  let mut ama = state[15]
  let mut ame = state[16]
  let mut ami = state[17]
  let mut amo = state[18]
  let mut amu = state[19]
  let mut asa = state[20]
  let mut ase = state[21]
  let mut asi = state[22]
  let mut aso = state[23]
  let mut asu = state[24]
  let mut round = 0
  while round < NROUNDS {
    // Theta step: compute column parities | Theta 步：计算列奇偶性
    let mut bca = aba ^ aga ^ aka ^ ama ^ asa
    let mut bce = abe ^ age ^ ake ^ ame ^ ase
    let mut bci = abi ^ agi ^ aki ^ ami ^ asi
    let mut bco = abo ^ ago ^ ako ^ amo ^ aso
    let mut bcu = abu ^ agu ^ aku ^ amu ^ asu

    // Combined Rho, Pi, Chi, Iota steps | 组合的 Rho, Pi, Chi, Iota 步骤
    let mut da = bcu ^ KeccakState::rol(bce, 1)
    let mut de = bca ^ KeccakState::rol(bci, 1)
    let mut di = bce ^ KeccakState::rol(bco, 1)
    let mut d_o = bci ^ KeccakState::rol(bcu, 1)
    let mut du = bco ^ KeccakState::rol(bca, 1)
    aba = aba ^ da
    bca = aba
    age = age ^ de
    bce = KeccakState::rol(age, 44)
    aki = aki ^ di
    bci = KeccakState::rol(aki, 43)
    amo = amo ^ d_o
    bco = KeccakState::rol(amo, 21)
    asu = asu ^ du
    bcu = KeccakState::rol(asu, 14)
    let mut eba = bca ^ (bce.lnot() & bci)
    eba = eba ^ keccakf_round_constants[round]
    let mut ebe = bce ^ (bci.lnot() & bco)
    let mut ebi = bci ^ (bco.lnot() & bcu)
    let mut ebo = bco ^ (bcu.lnot() & bca)
    let mut ebu = bcu ^ (bca.lnot() & bce)
    abo = abo ^ d_o
    bca = KeccakState::rol(abo, 28)
    agu = agu ^ du
    bce = KeccakState::rol(agu, 20)
    aka = aka ^ da
    bci = KeccakState::rol(aka, 3)
    ame = ame ^ de
    bco = KeccakState::rol(ame, 45)
    asi = asi ^ di
    bcu = KeccakState::rol(asi, 61)
    let mut ega = bca ^ (bce.lnot() & bci)
    let mut ege = bce ^ (bci.lnot() & bco)
    let mut egi = bci ^ (bco.lnot() & bcu)
    let mut ego = bco ^ (bcu.lnot() & bca)
    let mut egu = bcu ^ (bca.lnot() & bce)
    abe = abe ^ de
    bca = KeccakState::rol(abe, 1)
    agi = agi ^ di
    bce = KeccakState::rol(agi, 6)
    ako = ako ^ d_o
    bci = KeccakState::rol(ako, 25)
    amu = amu ^ du
    bco = KeccakState::rol(amu, 8)
    asa = asa ^ da
    bcu = KeccakState::rol(asa, 18)
    let mut eka = bca ^ (bce.lnot() & bci)
    let mut eke = bce ^ (bci.lnot() & bco)
    let mut eki = bci ^ (bco.lnot() & bcu)
    let mut eko = bco ^ (bcu.lnot() & bca)
    let mut eku = bcu ^ (bca.lnot() & bce)
    abu = abu ^ du
    bca = KeccakState::rol(abu, 27)
    aga = aga ^ da
    bce = KeccakState::rol(aga, 36)
    ake = ake ^ de
    bci = KeccakState::rol(ake, 10)
    ami = ami ^ di
    bco = KeccakState::rol(ami, 15)
    aso = aso ^ d_o
    bcu = KeccakState::rol(aso, 56)
    let mut ema = bca ^ (bce.lnot() & bci)
    let mut eme = bce ^ (bci.lnot() & bco)
    let mut emi = bci ^ (bco.lnot() & bcu)
    let mut emo = bco ^ (bcu.lnot() & bca)
    let mut emu = bcu ^ (bca.lnot() & bce)
    abi = abi ^ di
    bca = KeccakState::rol(abi, 62)
    ago = ago ^ d_o
    bce = KeccakState::rol(ago, 55)
    aku = aku ^ du
    bci = KeccakState::rol(aku, 39)
    ama = ama ^ da
    bco = KeccakState::rol(ama, 41)
    ase = ase ^ de
    bcu = KeccakState::rol(ase, 2)
    let mut esa = bca ^ (bce.lnot() & bci)
    let mut ese = bce ^ (bci.lnot() & bco)
    let mut esi = bci ^ (bco.lnot() & bcu)
    let mut eso = bco ^ (bcu.lnot() & bca)
    let mut esu = bcu ^ (bca.lnot() & bce)

    // Second theta step | 第二个 theta 步骤
    bca = eba ^ ega ^ eka ^ ema ^ esa
    bce = ebe ^ ege ^ eke ^ eme ^ ese
    bci = ebi ^ egi ^ eki ^ emi ^ esi
    bco = ebo ^ ego ^ eko ^ emo ^ eso
    bcu = ebu ^ egu ^ eku ^ emu ^ esu

    // Second combined step | 第二个组合步骤
    da = bcu ^ KeccakState::rol(bce, 1)
    de = bca ^ KeccakState::rol(bci, 1)
    di = bce ^ KeccakState::rol(bco, 1)
    d_o = bci ^ KeccakState::rol(bcu, 1)
    du = bco ^ KeccakState::rol(bca, 1)
    eba = eba ^ da
    bca = eba
    ege = ege ^ de
    bce = KeccakState::rol(ege, 44)
    eki = eki ^ di
    bci = KeccakState::rol(eki, 43)
    emo = emo ^ d_o
    bco = KeccakState::rol(emo, 21)
    esu = esu ^ du
    bcu = KeccakState::rol(esu, 14)
    aba = bca ^ (bce.lnot() & bci)
    aba = aba ^ keccakf_round_constants[round + 1]
    abe = bce ^ (bci.lnot() & bco)
    abi = bci ^ (bco.lnot() & bcu)
    abo = bco ^ (bcu.lnot() & bca)
    abu = bcu ^ (bca.lnot() & bce)
    ebo = ebo ^ d_o
    bca = KeccakState::rol(ebo, 28)
    egu = egu ^ du
    bce = KeccakState::rol(egu, 20)
    eka = eka ^ da
    bci = KeccakState::rol(eka, 3)
    eme = eme ^ de
    bco = KeccakState::rol(eme, 45)
    esi = esi ^ di
    bcu = KeccakState::rol(esi, 61)
    aga = bca ^ (bce.lnot() & bci)
    age = bce ^ (bci.lnot() & bco)
    agi = bci ^ (bco.lnot() & bcu)
    ago = bco ^ (bcu.lnot() & bca)
    agu = bcu ^ (bca.lnot() & bce)
    ebe = ebe ^ de
    bca = KeccakState::rol(ebe, 1)
    egi = egi ^ di
    bce = KeccakState::rol(egi, 6)
    eko = eko ^ d_o
    bci = KeccakState::rol(eko, 25)
    emu = emu ^ du
    bco = KeccakState::rol(emu, 8)
    esa = esa ^ da
    bcu = KeccakState::rol(esa, 18)
    aka = bca ^ (bce.lnot() & bci)
    ake = bce ^ (bci.lnot() & bco)
    aki = bci ^ (bco.lnot() & bcu)
    ako = bco ^ (bcu.lnot() & bca)
    aku = bcu ^ (bca.lnot() & bce)
    ebu = ebu ^ du
    bca = KeccakState::rol(ebu, 27)
    ega = ega ^ da
    bce = KeccakState::rol(ega, 36)
    eke = eke ^ de
    bci = KeccakState::rol(eke, 10)
    emi = emi ^ di
    bco = KeccakState::rol(emi, 15)
    eso = eso ^ d_o
    bcu = KeccakState::rol(eso, 56)
    ama = bca ^ (bce.lnot() & bci)
    ame = bce ^ (bci.lnot() & bco)
    ami = bci ^ (bco.lnot() & bcu)
    amo = bco ^ (bcu.lnot() & bca)
    amu = bcu ^ (bca.lnot() & bce)
    ebi = ebi ^ di
    bca = KeccakState::rol(ebi, 62)
    ego = ego ^ d_o
    bce = KeccakState::rol(ego, 55)
    eku = eku ^ du
    bci = KeccakState::rol(eku, 39)
    ema = ema ^ da
    bco = KeccakState::rol(ema, 41)
    ese = ese ^ de
    bcu = KeccakState::rol(ese, 2)
    asa = bca ^ (bce.lnot() & bci)
    ase = bce ^ (bci.lnot() & bco)
    asi = bci ^ (bco.lnot() & bcu)
    aso = bco ^ (bcu.lnot() & bca)
    asu = bcu ^ (bca.lnot() & bce)
    round += 2 // Process two rounds at once | 一次处理两轮
  }
  // Copy back to state | 复制回状态数组
  state[0] = aba
  state[1] = abe
  state[2] = abi
  state[3] = abo
  state[4] = abu
  state[5] = aga
  state[6] = age
  state[7] = agi
  state[8] = ago
  state[9] = agu
  state[10] = aka
  state[11] = ake
  state[12] = aki
  state[13] = ako
  state[14] = aku
  state[15] = ama
  state[16] = ame
  state[17] = ami
  state[18] = amo
  state[19] = amu
  state[20] = asa
  state[21] = ase
  state[22] = asi
  state[23] = aso
  state[24] = asu
}

///|
/// Incremental absorb for Keccak | Keccak 的增量吸收
/// Processes input data in blocks, updating the state incrementally
/// 以块为单位处理输入数据，增量更新状态
fn keccak_absorb(
  state : KeccakState,
  r : UInt,
  input : Array[Byte],
  inlen : UInt,
) -> Unit {
  let mut idx = 0
  let mut pos = state.pos
  let mut inlen = inlen
  while pos + inlen >= r {
    // Fill current block and permute | 填充当前块并置换
    for i in pos..<r {
      let index = (i >> 3).reinterpret_as_int()
      let offset = (i & 7).reinterpret_as_int()
      state.s[index] = state.s[index] ^ (input[idx].to_uint64() << (8 * offset))
      idx += 1
    }
    inlen -= r - pos
    keccakf1600_statepermute(state.s)
    pos = 0
  }
  // Absorb remaining partial block | 吸收剩余的部分块
  for i in pos..<(pos + inlen) {
    let index = (i >> 3).reinterpret_as_int()
    let offset = (i & 7).reinterpret_as_int()
    state.s[index] = state.s[index] ^ (input[idx].to_uint64() << (8 * offset))
    idx += 1
  }
  state.pos = pos + inlen
}

///|
/// Finalizes the Keccak absorb phase by adding appropriate padding and
/// termination bits to mark the end of input data.
///
/// Parameters:
///
/// * `state` : The Keccak state array containing 25 64-bit words representing
///   the internal state.
/// * `pos` : Current position in bytes within the rate block where the next
///   input byte would be absorbed.
/// * `rate` : The rate parameter in bytes, determining the size of the
///   absorbing capacity for this Keccak variant.
/// * `padding_byte` : The padding byte value that identifies the specific
///   Keccak variant (e.g., 0x1F for SHAKE, 0x06 for SHA-3).
///
/// Panics if `rate` is less than 8 bytes, as this would cause an underflow when
/// calculating the final state index.
fn keccak_finalize(
  s : FixedArray[UInt64],
  pos : UInt,
  r : UInt,
  p : Byte,
) -> Unit {
  let index = (pos >> 3).reinterpret_as_int()
  let offset = (pos & 7).reinterpret_as_int()
  s[index] = s[index] ^ (p.to_uint64() << (8 * offset))
  let index = ((r >> 3) - 1).reinterpret_as_int()
  s[index] = s[index] ^ (1UL << 63)
}

///|
/// Extracts output bytes from the Keccak state, applying permutation when
/// necessary.
///
/// This function implements the "squeeze" phase of the Keccak sponge
/// construction. It extracts the requested number of output bytes from the
/// internal state, automatically applying the Keccak-f\[1600] permutation when
/// the current block is exhausted and more output is needed.
///
/// Parameters:
///
/// * `out` : The output buffer to write the extracted bytes to.
/// * `outlen` : The number of bytes to extract.
/// * `s` : The Keccak state array (25 64-bit words).
/// * `pos` : The current position within the rate block (in bytes).
/// * `r` : The rate (block size) in bytes for the specific Keccak variant.
///
/// Returns the updated position within the rate block after extraction.
///
fn keccak_squeeze(
  out : MutArrayView[Byte],
  outlen : UInt,
  s : FixedArray[UInt64],
  pos : UInt,
  r : UInt,
) -> UInt {
  let mut pos = pos
  let mut outlen = outlen
  while outlen != 0 {
    if pos == r {
      // Permute state when current block is exhausted | 当前块用尽时置换状态
      keccakf1600_statepermute(s)
      pos = 0
    }
    let mut i = pos
    let mut idx = 0
    while i < r && i < pos + outlen {
      let index = (i >> 3).reinterpret_as_int()
      let offset = (i & 7).reinterpret_as_int()
      out.set(idx, (s[index] >> (8 * offset)).to_byte())
      idx += 1
      i += 1
    }
    outlen -= i - pos
    pos = i
  }
  return pos
}

///|
/// Non-incremental absorb for Keccak | Keccak 的非增量吸收
/// Initializes state, absorbs all input, and finalizes in one go
/// 初始化状态，吸收所有输入，并一次性完成
fn keccak_absorb_once(
  s : FixedArray[UInt64],
  r : UInt,
  input : Array[Byte],
  inlen : UInt,
  p : Byte,
) -> Unit {
  let mut inlen = inlen.reinterpret_as_int()
  let r = r.reinterpret_as_int()
  let mut idx = 0
  s.fill(0)
  while inlen >= r {
    // Process full blocks | 处理完整块
    for i in 0..<(r / 8) {
      let start = idx + 8 * i
      s[i] = s[i] ^ load64(input[start:start + 8].to_array())
    }
    idx += r
    inlen -= r
    keccakf1600_statepermute(s)
  }
  // Absorb partial block and add padding | 吸收部分块并添加填充
  for i in 0..<inlen {
    s[i / 8] = s[i / 8] ^ (input[idx + i].to_uint64() << (8 * (i % 8)))
  }
  s[inlen / 8] = s[inlen / 8] ^ (p.to_uint64() << (8 * (inlen % 8)))
  s[(r - 1) / 8] = s[(r - 1) / 8] ^ (1UL << 63)
}

///|
/// Extracts multiple full blocks of output data from the Keccak state by
/// repeatedly applying the Keccak permutation function.
///
/// Parameters:
///
/// * `out` : `MutArrayView[Byte]` - The output buffer where extracted blocks will
///   be written.
/// * `nblocks` : `UInt` - The number of complete blocks to extract from the
///   state.
/// * `s` : `FixedArray[UInt64]` - The 25-element Keccak state array containing
///   the internal state.
/// * `r` : `UInt` - The rate parameter (block size in bytes) for the Keccak
///   variant being used.
///
/// Panics if the output buffer `out` is too small to accommodate `nblocks * r`
/// bytes.
///
fn keccak_squeezeblocks(
  out : MutArrayView[Byte],
  nblocks : UInt,
  s : FixedArray[UInt64],
  r : UInt,
) -> Unit {
  let mut nblocks = nblocks
  let r = r.reinterpret_as_int()
  let mut idx = 0
  while nblocks > 0 {
    keccakf1600_statepermute(s)
    // Extract full block | 提取完整块
    for i in 0..<(r >> 3) {
      let arr : Array[Byte] = Array::make(8, 0)
      store64(arr, s[i])
      for j in 0..<8 {
        out.set(idx + 8 * i + j, arr[j])
      }
    }
    idx += r
    nblocks -= 1
  }
}

///|
/// Incrementally absorbs input data into a SHAKE128 state for cryptographic
/// hashing.
///
/// This function is part of the SHAKE128 extendable-output function (XOF)
/// implementation. It processes input data in chunks, updating the internal
/// Keccak state without finalizing the hash. Multiple calls to this function
/// can be made to absorb data incrementally before calling the finalize
/// function.
///
/// Parameters:
///
/// * `state` : The SHAKE128 state to absorb data into. The state maintains the
///   current position and internal Keccak state array.
/// * `input` : The byte array containing the data to be absorbed into the hash
///   state.
/// * `inlen` : The number of bytes from the input array to process. This allows
///   processing only a portion of the input array if needed.
///
/// Example:
///
/// ```moonbit
/// let state = KeccakState::default()
/// let data : Array[Byte] = "Hello, World!".to_bytes().to_array()
/// shake128_absorb(state, data, data.length().reinterpret_as_uint())
/// // Continue absorbing more data if needed
/// let more_data : Array[Byte] = " More data".to_bytes().to_array()
/// shake128_absorb(state, more_data, more_data.length().reinterpret_as_uint())
/// // Finally call shake128_finalize(state) to complete the absorption phase
/// ```
///
pub fn shake128_absorb(
  state : KeccakState,
  input : Array[Byte],
  inlen : UInt,
) -> Unit {
  keccak_absorb(state, SHAKE128_RATE, input, inlen)
}

///|
/// Finalizes the SHAKE128 absorbing phase by applying proper padding and
/// transitions the state to the squeezing phase.
///
/// Parameters:
///
/// * `state` : The SHAKE128 state that has been absorbing input data and needs
///   to be finalized.
///
/// Example:
///
/// ```moonbit
/// let state = KeccakState::default()
/// let input : Array[Byte] = "Hello, World!".to_bytes().to_array()
/// shake128_absorb(state, input, input.length().reinterpret_as_uint())
/// shake128_finalize(state)
/// // State is now ready for squeezing output
/// ```
///
pub fn shake128_finalize(state : KeccakState) -> Unit {
  keccak_finalize(state.s, state.pos, SHAKE128_RATE, 0x1F)
  state.pos = SHAKE128_RATE
}

///|
/// Extracts full blocks of output data from a SHAKE128 state.
///
/// Parameters:
///
/// * `output` : The buffer to store the extracted output bytes.
/// * `nblocks` : The number of complete blocks to extract from the state.
/// * `s` : The SHAKE128 state to extract data from.
///
/// Example:
///
/// ```moonbit
/// let state = KeccakState::default()
/// // ... after initializing and finalizing the state ...
/// let output: Array[Byte] = Array::make(336, 0) // 2 blocks * 168 bytes per block
/// shake128_squeezeblocks(output, 2, state)
/// ```
///
pub fn shake128_squeezeblocks(
  output : MutArrayView[Byte],
  nblocks : UInt,
  s : KeccakState,
) -> Unit {
  keccak_squeezeblocks(output, nblocks, s.s, SHAKE128_RATE)
}

///|
/// Incrementally absorbs input data into the SHAKE256 state during the
/// absorbing phase.
///
/// This function allows you to feed data to SHAKE256 in multiple chunks rather
/// than all at once. The state maintains its position internally, so you can
/// call this function multiple times with different input chunks before
/// finalizing and squeezing output.
///
/// Parameters:
///
/// * `state` (`KeccakState`) : The SHAKE256 state object that maintains the
///   internal hash state.
/// * `input` (`Array[Byte]`) : The byte array containing the data to absorb.
/// * `inlen` (`UInt`) : The number of bytes to absorb from the input array.
///
/// Example:
///
/// ```moonbit
/// let state = @ruifeng/moondsa.KeccakState::default()
/// let chunk1 : Array[Byte] = b"Hello, ".to_array()
/// let chunk2 : Array[Byte] = b"World!".to_array()
///
/// // Absorb data incrementally
/// @ruifeng/moondsa.shake256_absorb(state, chunk1, 7U)
/// @ruifeng/moondsa.shake256_absorb(state, chunk2, 6U)
///
/// // Finalize before squeezing
/// @ruifeng/moondsa.shake256_finalize(state)
///
/// // Now squeeze output
/// let output : Array[Byte] = Array::make(32, 0)
/// @ruifeng/moondsa.shake256_squeeze(output, 32U, state)
/// ```
///
pub fn shake256_absorb(
  state : KeccakState,
  input : Array[Byte],
  inlen : UInt,
) -> Unit {
  keccak_absorb(state, SHAKE256_RATE, input, inlen)
}

///|
/// Finalizes the SHAKE256 absorbing phase by applying proper padding and
/// preparing the state for output extraction.
///
/// Parameters:
///
/// * `state` : The SHAKE256 Keccak state to finalize, which has been absorbing
///   input data.
///
/// Example:
///
/// ```moonbit
/// let state = @ruifeng/moondsa.KeccakState::default()
/// let input : Array[Byte] = b"hello world".to_array()
/// @ruifeng/moondsa.shake256_absorb(state, input, 11)
/// @ruifeng/moondsa.shake256_finalize(state)
/// // State is now ready for squeezing output
/// ```
///
pub fn shake256_finalize(state : KeccakState) -> Unit {
  keccak_finalize(state.s, state.pos, SHAKE256_RATE, 0x1F)
  state.pos = SHAKE256_RATE
}

///|
/// Extracts output bytes from a SHAKE256 state in the squeezing phase.
///
/// Parameters:
///
/// * `out` : The output buffer to write the extracted bytes to.
/// * `outlen` : The number of bytes to extract from the state.
/// * `state` : The SHAKE256 state to squeeze from. The state's internal
///   position will be updated to reflect the new position after squeezing.
///
/// Example:
///
/// ```moonbit
/// // Initialize SHAKE256 state and absorb some data
/// let state = KeccakState::default()
/// let input : Array[Byte] = "Hello, World!".to_bytes().to_array()
/// shake256_absorb(state, input, input.length().reinterpret_as_uint())
/// shake256_finalize(state)
///
/// // Squeeze 32 bytes of output
/// let output : Array[Byte] = Array::make(32, 0)
/// shake256_squeeze(output.mut_view(), 32, state)
/// ```
///
pub fn shake256_squeeze(
  out : MutArrayView[Byte],
  outlen : UInt,
  state : KeccakState,
) -> Unit {
  state.pos = keccak_squeeze(out, outlen, state.s, state.pos, SHAKE256_RATE)
}

///|
/// Performs complete SHAKE256 absorption in a single operation, processing all
/// input data and finalizing the state.
///
/// Parameters:
///
/// * `state` : The Keccak state to be initialized and used for absorption.
/// * `input` : The byte array containing the data to be absorbed.
/// * `inlen` : The number of bytes from the input array to process.
///
/// Example:
///
/// ```moonbit
/// let state = @ruifeng/moondsa.KeccakState::default()
/// let data : Array[Byte] = [0, 1, 2, 3]
/// @ruifeng/moondsa.shake256_absorb_once(state, data, 4)
/// // State is now ready for squeezing output
/// ```
///
pub fn shake256_absorb_once(
  state : KeccakState,
  input : Array[Byte],
  inlen : UInt,
) -> Unit {
  keccak_absorb_once(state.s, SHAKE256_RATE, input, inlen, 0x1F)
  state.pos = SHAKE256_RATE
}

///|
/// Extracts full blocks of output data from a SHAKE256 state.
///
/// Parameters:
///
/// * `out` : The output array to store the extracted bytes.
/// * `nblocks` : The number of full blocks to extract from the state.
/// * `state` : The SHAKE256 state to extract data from.
///
/// Examples:
///
/// ```moonbit
/// // Initialize SHAKE256 state and absorb some input
/// let state = KeccakState::default()
/// shake256_absorb_once(state, [1, 2, 3, 4], 4)
///
/// // Extract 2 full blocks (272 bytes total for SHAKE256)
/// let output : Array[Byte] = Array::make(272, 0)
/// shake256_squeezeblocks(output, 2, state)
/// ```
///
pub fn shake256_squeezeblocks(
  out : Array[Byte],
  nblocks : UInt,
  state : KeccakState,
) -> Unit {
  keccak_squeezeblocks(out.mut_view(), nblocks, state.s, SHAKE256_RATE)
}

///|
/// SHAKE256 complete operation | SHAKE256 完整操作
/// Performs complete SHAKE256 hash: absorb input and squeeze output
/// 执行完整的 SHAKE256 哈希：吸收输入并挤压输出
pub fn shake256(
  output~ : Array[Byte],
  outlen : UInt,
  input~ : Array[Byte],
  inlen : UInt,
) -> Unit {
  let mut outlen = outlen
  let state = KeccakState::default()
  shake256_absorb_once(state, input, inlen)
  let nblocks = outlen / SHAKE256_RATE
  shake256_squeezeblocks(output, nblocks, state)
  outlen -= nblocks * SHAKE256_RATE
  let idx = nblocks * SHAKE256_RATE
  shake256_squeeze(
    output.mut_view(start=idx.reinterpret_as_int()),
    outlen,
    state,
  )
}

///|这里主要定义了一些外部api,同时为将来支持aes做准备

///|
/// Initializes a SHAKE128 stream for Dilithium cryptographic operations.
///
/// Parameters:
///
/// * `state` : The Keccak state to be initialized for streaming operations.
/// * `seed` : The seed bytes used for initialization (expected to be SEEDBYTES
///   length).
/// * `nonce` : A 16-bit nonce value to ensure unique stream initialization.
///
/// Example:
///
/// ```moonbit
/// let state = @ruifeng/moondsa.KeccakState::default()
/// let seed: Array[Byte] = Array::make(32, 0) // SEEDBYTES length
/// let nonce = (42: UInt16)
/// @ruifeng/moondsa.stream128_init(state, seed, nonce)
/// ```
///
pub fn stream128_init(
  state : KeccakState,
  seed : Array[Byte],
  nonce : UInt16,
) -> Unit {
  dilithium_shake128_stream_init(state, seed, nonce)
}

///|
/// Squeezes multiple full blocks of output data from a SHAKE128 state.
///
/// Parameters:
///
/// * `out` : The output buffer where the squeezed data will be written.
/// * `outblocks` : The number of full blocks to squeeze from the state.
/// * `state` : The SHAKE128 state to squeeze data from.
///
pub fn stream128_squeezeblocks(
  out : MutArrayView[Byte],
  outblocks : UInt64,
  state : KeccakState,
) -> Unit {
  shake128_squeezeblocks(out, outblocks.to_uint(), state)
}

///|
/// Initializes a SHAKE128 stream for the CRYSTALS-Dilithium post-quantum
/// cryptographic scheme.
///
/// Parameters:
///
/// * `state` : The Keccak state to be initialized for streaming.
/// * `seed` : A byte array containing the seed data, expected to be of length
///   `SEEDBYTES`.
/// * `nonce` : A 16-bit unsigned integer used as a unique identifier for this
///   stream instance.
///
/// Example:
///
/// ```moonbit
/// let state = KeccakState::default()
/// let seed: Array[Byte] = Array::make(SEEDBYTES, 0) // Create seed of appropriate size
/// @ruifeng/moondsa.dilithium_shake128_stream_init(state, seed, (42: UInt16))
/// ```
///
pub fn dilithium_shake128_stream_init(
  state : KeccakState,
  seed : Array[Byte],
  nonce : UInt16,
) -> Unit {
  let t = [nonce.to_byte(), (nonce >> 8).to_byte()]
  state.init()
  shake128_absorb(state, seed, SEEDBYTES.reinterpret_as_uint())
  shake128_absorb(state, t, 2)
  shake128_finalize(state)
}

///|
/// Initializes a SHAKE256 stream state for cryptographic operations with a seed
/// and nonce.
///
/// Parameters:
///
/// * `state` : The KeccakState object to be initialized for SHAKE256 streaming.
/// * `seed` : The cryptographic seed bytes used to initialize the stream state.
/// * `nonce` : A 16-bit nonce value to provide uniqueness for each stream
///   initialization.
///
/// Example:
///
/// ```moonbit
/// let state = KeccakState::default()
/// let seed : Array[Byte] = Array::make(CRHBYTES, b'A') // 64-byte seed
/// stream256_init(state, seed, (42: UInt16))
/// ```
///
pub fn stream256_init(
  state : KeccakState,
  seed : Array[Byte],
  nonce : UInt16,
) -> Unit {
  dilithium_shake256_stream_init(state, seed, nonce)
}

///|
/// Extracts multiple full blocks of output from a SHAKE256 stream state.
///
/// Parameters:
///
/// * `out` : The output array where the extracted bytes will be stored.
/// * `outblocks` : The number of blocks to extract from the stream.
/// * `state` : The SHAKE256 stream state to extract blocks from.
pub fn stream256_squeezeblocks(
  out : Array[Byte],
  outblocks : UInt64,
  state : KeccakState,
) -> Unit {
  shake256_squeezeblocks(out, outblocks.to_uint(), state)
}

///|
/// Initializes a SHAKE256 stream for Dilithium cryptographic operations with a
/// seed and nonce.
///
/// Parameters:
///
/// * `state` : The Keccak state to initialize for SHAKE256 streaming.
/// * `seed` : The cryptographic seed bytes used for initialization.
/// * `nonce` : A 16-bit nonce value to ensure uniqueness of the stream.
///
/// Example:
///
/// ```moonbit
/// let state = KeccakState::default()
/// let seed : Array[Byte] = Array::make(CRHBYTES, 0) // 64-byte seed
/// let nonce = (42: UInt16)
/// dilithium_shake256_stream_init(state, seed, nonce)
/// ```
///
pub fn dilithium_shake256_stream_init(
  state : KeccakState,
  seed : Array[Byte],
  nonce : UInt16,
) -> Unit {
  let t = [nonce.to_byte(), (nonce >> 8).to_byte()]
  state.init()
  shake256_absorb(state, seed, CRHBYTES.reinterpret_as_uint())
  shake256_absorb(state, t, 2)
  shake256_finalize(state)
}
