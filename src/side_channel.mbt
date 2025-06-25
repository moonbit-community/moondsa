///|
pub fn ite(cond : Bool, a : Int, b : Int) -> Int {
  if cond {
    return a
  }
  if not(cond) {
    return b
  }
  0 // unreachable
}
