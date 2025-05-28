///|
const N : Int = @params.N

///|
const D : Int = @params.D

///|
pub struct Poly {
  coeffs : FixedArray[Int]
}

///|
impl Default for Poly with default() -> Poly {
  { coeffs: FixedArray::make(N, 0) }
}

///|
pub fn Poly::add(self : Poly, other : Poly) -> Unit {
  for i in 0..<N {
    self.coeffs[i] += other.coeffs[i]
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
