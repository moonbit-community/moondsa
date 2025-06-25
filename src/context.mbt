
///|
struct DilithiumContext {
  mut params_set : ParameterSet
  mut random : @random.Rand
}

///| 
fn DilithiumContext::new(
  level : SecurityLevel,
  random : @random.Rand
) -> DilithiumContext {
  let params_set = level.gen_params()
  { params_set, random }
}

///| default random is very dangerous, please use your own random source
pub let dilithium_context : DilithiumContext = DilithiumContext::new(
  Dilithium3,
  @random.Rand::new(),
) // default level

///|
pub fn DilithiumContext::set_level(
  self : DilithiumContext,
  level : SecurityLevel
) -> Unit {
  self.params_set = level.gen_params()
}

///|
pub fn DilithiumContext::get_params_set(
  self : DilithiumContext
) -> ParameterSet {
  self.params_set
}

///|
pub fn DilithiumContext::set_random(
  self : DilithiumContext,
  random : @random.Rand
) -> Unit {
  self.random = random
}

///|
pub fn DilithiumContext::get_random(self : DilithiumContext) -> @random.Rand {
  self.random
}
