///|
/// Global configuration and context management for the Dilithium signature scheme.
///
/// This module provides centralized configuration management for the Dilithium
/// signature implementation, including security level selection and random
/// number generator configuration. The context system allows runtime adjustment
/// of cryptographic parameters without recompilation.
///
/// # Security Levels
///
/// The Dilithium scheme supports three security levels that provide different
/// trade-offs between security strength and performance:
///
/// - **Dilithium2**: Provides 128-bit classical security equivalent
///   - Fastest performance, smallest signatures
///   - Suitable for most applications
///
/// - **Dilithium3**: Provides 192-bit classical security equivalent  
///   - Balanced security and performance
///   - Recommended for high-security applications
///
/// - **Dilithium5**: Provides 256-bit classical security equivalent
///   - Highest security level
///   - Largest signatures and slowest performance
///
/// # Usage Examples
///
/// ```moonbit
/// // Set security level
/// @ruifeng/moondsa.dilithium_context.set_level(SecurityLevel::Dilithium3)
/// 
/// // Configure custom random number generator
/// let custom_rand = @random.Rand::new()
/// @ruifeng/moondsa.dilithium_context.set_random(custom_rand)
/// 
/// // Get current parameters
/// let params = @ruifeng/moondsa.dilithium_context.get_params_set()
/// ```

///|
/// Global configuration context for the Dilithium signature scheme.
///
/// This structure maintains the current security parameters and random number
/// generator configuration for all cryptographic operations.
struct DilithiumContext {
  mut params_set : ParameterSet // Current security parameters
  mut random : @random.Rand // Random number generator
}

///| 
fn DilithiumContext::new(
  level : SecurityLevel,
  random : @random.Rand,
) -> DilithiumContext {
  let params_set = level.gen_paramset()
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
  level : SecurityLevel,
) -> Unit {
  self.params_set = level.gen_paramset()
}

///|
pub fn DilithiumContext::get_params_set(
  self : DilithiumContext,
) -> ParameterSet {
  self.params_set
}

///|
pub fn DilithiumContext::set_random(
  self : DilithiumContext,
  random : @random.Rand,
) -> Unit {
  self.random = random
}

///|
pub fn DilithiumContext::get_random(self : DilithiumContext) -> @random.Rand {
  self.random
}
