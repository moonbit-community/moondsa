///|
pub struct Polyveck {
  vec : Array[Poly]
}

///|
impl Default for Polyveck with default() -> Polyveck {
  let k = @config.dilithium_context.get_params_set().k
  { vec: Array::make(k, Poly::new()) }
}

///|
pub struct Polyvecl {
  vec : Array[Poly]
}

///|
impl Default for Polyvecl with default() -> Polyvecl {
  let l = @config.dilithium_context.get_params_set().l
  { vec: Array::make(l, Poly::new()) }
}

///|
pub fn Polyveck::matrix_expand(
  mat : Array[Polyveck],
  rho : Array[Byte]
) -> Unit {
  let k = @config.dilithium_context.get_params_set().k
  let l = @config.dilithium_context.get_params_set().l
  for i in 0..<k {
    for j in 0..<l {
      mat[i].vec[j].uniform(rho, ((i << 8) + j).to_uint16())
    }
  }
}
