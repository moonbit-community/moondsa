///|
const N : Int = @config.N

///|
const D : Int = @config.D

///|
const D_SHL : Int = 1 << (D - 1)

///|
pub struct Poly {
  coeffs : Array[Int]
}

///|
impl Default for Poly with default() -> Poly {
  { coeffs: Array::make(N, 0) }
}

///|
pub fn Poly::new() -> Poly {
  Poly::default()
}

///|
pub fn Poly::add(self : Poly, other : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] += other.coeffs[i]
  }
}

///|
pub fn Poly::reduce(self : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = reduce32(self.coeffs[i])
  }
}

///|
pub fn Poly::caddq(self : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = caddq(self.coeffs[i])
  }
}

///|
pub fn Poly::sub(self : Poly, other : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] -= other.coeffs[i]
  }
}

///|
pub fn Poly::shiftl(self : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = self.coeffs[i] << D
  }
}

///|
pub fn Poly::ntt(self : Poly) -> Unit {
  ntt(self.coeffs)
}

///|
pub fn Poly::inv_ntt_to_mont(self : Poly) -> Unit {
  inv_ntt_to_mont(self.coeffs)
}

///|
pub fn Poly::pointwise_montgomery(self : Poly, other : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = montgomery_reduce(
      self.coeffs[i].to_int64() * other.coeffs[i].to_int64(),
    )
  }
}

///|
pub fn Poly::decompose(self : Poly, other : Poly) -> Unit {
  for i in 0..<N {
    let (a0, a1) = decompose(self.coeffs[i])
    self.coeffs[i] = a1
    other.coeffs[i] = a0
  }
}

///|
pub fn Poly::make_hint(h : Poly, a0 : Poly, a1 : Poly) -> Int {
  let mut s = 0
  for i in 0..<N {
    h.coeffs[i] = make_hint(a0.coeffs[i], a1.coeffs[i]).to_int()
    s += h.coeffs[i]
  }
  s
}

///|
pub fn Poly::use_hint(self : Poly, h : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] = use_hint(self.coeffs[i], h.coeffs[i].to_byte())
  }
}
