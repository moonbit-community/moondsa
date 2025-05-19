///| Reference: https://github.com/Argyle-Software/dilithium/blob/master/src/fips202.rs
/// 
/// 
pub const SHAKE128_RATE : UInt = 168

///|
pub const SHAKE256_RATE : UInt = 136

///|
const NROUNDS : Int = 24

///|
pub struct KeccakState {
  s : FixedArray[UInt64]
  mut pos : UInt
} derive(Show)

///|
impl Default for KeccakState with default() {
  { s: FixedArray::make(25, 0), pos: 0 }
}

///|
pub fn KeccakState::init(self : KeccakState) -> Unit {
  self.s.fill(0)
  self.pos = 0
}

///|
fn KeccakState::rol(a : UInt64, offset : Int) -> UInt64 {
  (a << offset) | (a >> (64 - offset))
}

///|
pub fn load64(x : Array[Byte]) -> UInt64 {
  let mut r = 0UL
  for i in 0..<8 {
    let v : UInt64 = x[i].to_uint64() << (8 * i)
    r = r | v
  }
  r
}

///|
pub fn store64(x : Array[Byte], u : UInt64) -> Unit {
  for i in 0..<8 {
    x[i] = (u >> (8 * i)).to_byte()
  }
}

///|
let keccakf_round_constants = [
  0x0000000000000001UL, 0x0000000000008082UL, 0x800000000000808aUL, 0x8000000080008000UL,
  0x000000000000808bUL, 0x0000000080000001UL, 0x8000000080008081UL, 0x8000000000008009UL,
  0x000000000000008aUL, 0x0000000000000088UL, 0x0000000080008009UL, 0x000000008000000aUL,
  0x000000008000808bUL, 0x800000000000008bUL, 0x8000000000008089UL, 0x8000000000008003UL,
  0x8000000000008002UL, 0x8000000000000080UL, 0x000000000000800aUL, 0x800000008000000aUL,
  0x8000000080008081UL, 0x8000000000008080UL, 0x0000000080000001UL, 0x8000000080008008UL,
]

///| The Keccak F1600 Permutation
pub fn keccakf1600_statepermute(state : FixedArray[UInt64]) -> Unit {
  //copyFromState(A, state)
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
    //    prepareTheta
    let mut bca = aba ^ aga ^ aka ^ ama ^ asa
    let mut bce = abe ^ age ^ ake ^ ame ^ ase
    let mut bci = abi ^ agi ^ aki ^ ami ^ asi
    let mut bco = abo ^ ago ^ ako ^ amo ^ aso
    let mut bcu = abu ^ agu ^ aku ^ amu ^ asu

    //thetaRhoPiChiIotaPrepareTheta(round  , A, E)
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

    //    prepareTheta
    bca = eba ^ ega ^ eka ^ ema ^ esa
    bce = ebe ^ ege ^ eke ^ eme ^ ese
    bci = ebi ^ egi ^ eki ^ emi ^ esi
    bco = ebo ^ ego ^ eko ^ emo ^ eso
    bcu = ebu ^ egu ^ eku ^ emu ^ esu

    //thetaRhoPiChiIotaPrepareTheta(round+1, E, A)
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
    round += 2
  }
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
fn keccak_absorb(
  state : KeccakState,
  r : UInt,
  input : Array[Byte],
  inlen : UInt
) -> Unit {
  let mut idx = 0
  let mut pos = state.pos
  let mut inlen = inlen
  while pos + inlen >= r {
    for i in pos..<r {
      let i = i.reinterpret_as_int()
      state.s[i / 8] = state.s[i / 8] ^
        (input[idx].to_uint64() << (8 * (i % 8)))
      idx += 1
    }
    inlen -= r - pos
    keccakf1600_statepermute(state.s)
    pos = 0
  }
  for i in pos..<(pos + inlen) {
    let i = i.reinterpret_as_int()
    state.s[i / 8] = state.s[i / 8] ^ (input[idx].to_uint64() << (8 * (i % 8)))
    idx += 1
  }
  state.pos = pos + inlen
}

///| Finalize absorb state
fn keccak_finalize(
  s : FixedArray[UInt64],
  pos : UInt,
  r : UInt,
  p : Byte
) -> Unit {
  let pos = pos.reinterpret_as_int()
  let r = r.reinterpret_as_int()
  s[pos / 8] = s[pos / 8] ^ (p.to_uint64() << (8 * (pos % 8)))
  s[r / 8 - 1] = s[r / 8 - 1] ^ (1UL << 63)
}

///| Squeeze step of Keccak. Squeezes arbitratrily many bytes.
///  Modifies the state. Can be called multiple times to keep
///  squeezing, i.e., is incremental.
///
// Returns new position pos in current block
fn keccak_squeeze(
  out : ArrayView[Byte],
  outlen : UInt,
  s : FixedArray[UInt64],
  pos : UInt,
  r : UInt
) -> UInt {
  let mut pos = pos
  let mut outlen = outlen
  while outlen != 0 {
    if pos == r {
      keccakf1600_statepermute(s)
      pos = 0
    }
    let mut i = pos
    let mut idx = 0
    while i < r && i < pos + outlen {
      let j = i.reinterpret_as_int()
      out[idx] = (s[j / 8] >> (8 * (j % 8))).to_byte()
      idx += 1
      i += 1
    }
    outlen -= i - pos
    pos = i
  }
  return pos
}

///| Absorb step of Keccak;
/// non-incremental, starts by zeroeing the state.
fn keccak_absorb_once(
  s : FixedArray[UInt64],
  r : UInt,
  input : Array[Byte],
  inlen : UInt,
  p : Byte
) -> Unit {
  let mut inlen = inlen.reinterpret_as_int()
  let r = r.reinterpret_as_int()
  let mut idx = 0
  s.fill(0)
  while inlen >= r {
    for i in 0..<(r / 8) {
      let start = idx + 8 * i
      s[i] = s[i] ^ load64(input[start:start + 8].to_array())
    }
    idx += r
    inlen -= r
    keccakf1600_statepermute(s)
  }
  for i in 0..<inlen {
    s[i / 8] = s[i / 8] ^ (input[idx + i].to_uint64() << (8 * (i % 8)))
  }
  s[inlen / 8] = s[inlen / 8] ^ (p.to_uint64() << (8 * (inlen % 8)))
  s[(r - 1) / 8] = s[(r - 1) / 8] ^ (1UL << 63)
}

///| Squeeze step of Keccak. Squeezes full blocks of r bytes each.
///  Modifies the state. Can be called multiple times to keep
///  squeezing, i.e., is incremental. Assumes zero bytes of current
///  block have already been squeezed.
fn keccak_squeezeblocks(
  out : Array[Byte],
  nblocks : UInt,
  s : FixedArray[UInt64],
  r : UInt
) -> Unit {
  let mut nblocks = nblocks
  let r = r.reinterpret_as_int()
  let mut idx = 0
  while nblocks > 0 {
    keccakf1600_statepermute(s)
    for i in 0..<(r >> 3) {
      let arr : Array[Byte] = Array::make(8, 0)
      store64(arr, s[i])
      for j in 0..<8 {
        out[idx + 8 * i + j] = arr[j]
      }
    }
    idx += r
    nblocks -= 1
  }
}

///| Description: Absorb step of the SHAKE128 XOF; incremental.
pub fn shake128_absorb(
  state : KeccakState,
  input : Array[Byte],
  inlen : UInt
) -> Unit {
  keccak_absorb(state, SHAKE128_RATE, input, inlen)
}

///| Finalize absorb step of the SHAKE128 XOF.
pub fn shake128_finalize(state : KeccakState) -> Unit {
  keccak_finalize(state.s, state.pos, SHAKE128_RATE, 0x1F)
  state.pos = SHAKE128_RATE
}

///| Squeeze step of SHAKE128 XOF. Squeezes full blocks of
///  SHAKE128_RATE bytes each. Can be called multiple times
///  to keep squeezing. Assumes new block has not yet been
///  started (state->pos = SHAKE128_RATE).
pub fn shake128_squeezeblocks(
  output : Array[Byte],
  nblocks : UInt,
  s : KeccakState
) -> Unit {
  keccak_squeezeblocks(output, nblocks, s.s, SHAKE128_RATE)
}

///| Absorb step of the SHAKE256 XOF; incremental.
pub fn shake256_absorb(
  state : KeccakState,
  input : Array[Byte],
  inlen : UInt
) -> Unit {
  keccak_absorb(state, SHAKE256_RATE, input, inlen)
}

///| Finalize absorb step of the SHAKE256 XOF.*/
pub fn shake256_finalize(state : KeccakState) -> Unit {
  keccak_finalize(state.s, state.pos, SHAKE256_RATE, 0x1F)
  state.pos = SHAKE256_RATE
}

///|Squeeze step of SHAKE256 XOF. Squeezes arbitraily many
/// bytes. Can be called multiple times to keep squeezing.
pub fn shake256_squeeze(
  out : ArrayView[Byte],
  outlen : UInt,
  state : KeccakState
) -> Unit {
  state.pos = keccak_squeeze(out, outlen, state.s, state.pos, SHAKE256_RATE)
}

///| Initialize, absorb into and finalize SHAKE256 XOF; non-incremental.
pub fn shake256_absorb_once(
  state : KeccakState,
  input : Array[Byte],
  inlen : UInt
) -> Unit {
  keccak_absorb_once(state.s, SHAKE256_RATE, input, inlen, 0x1F)
  state.pos = SHAKE256_RATE
}

///| Squeeze step of SHAKE256 XOF. Squeezes full blocks of
///              SHAKE256_RATE bytes each. Can be called multiple times
///              to keep squeezing. Assumes next block has not yet been
///              started (state.pos = SHAKE256_RATE).
pub fn shake256_squeezeblocks(
  out : Array[Byte],
  nblocks : UInt,
  state : KeccakState
) -> Unit {
  keccak_squeezeblocks(out, nblocks, state.s, SHAKE256_RATE)
}

///| SHAKE256 XOF with non-incremental API
pub fn shake256(
  output : Array[Byte],
  outlen : UInt,
  input : Array[Byte],
  inlen : UInt
) -> Unit {
  let mut outlen = outlen
  let state = KeccakState::default()
  shake256_absorb_once(state, input, inlen)
  let nblocks = outlen / SHAKE256_RATE
  shake256_squeezeblocks(output, nblocks, state)
  outlen -= nblocks * SHAKE256_RATE
  let idx = nblocks * SHAKE256_RATE
  shake256_squeeze(output[idx.reinterpret_as_int():], outlen, state)
}
