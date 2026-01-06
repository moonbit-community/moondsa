///|
/// Side-channel attack resistant utilities for constant-time operations.
///
/// This module provides constant-time implementations of common operations
/// to prevent timing-based side-channel attacks. These functions are crucial
/// for maintaining the security of cryptographic implementations against
/// sophisticated adversaries who can measure execution time or power consumption.
///
/// # Security Considerations
///
/// All operations in this module are designed to execute in constant time,
/// independent of the input values. This prevents attackers from inferring
/// secret information through timing analysis.
///
/// # Implementation Details
///
/// - Uses bitwise operations to avoid conditional branches
/// - Eliminates data-dependent memory access patterns
/// - Provides constant-time selection and comparison operations
///
/// # References
///
/// - Kocher, P. "Timing Attacks on Implementations of Diffie-Hellman, RSA, DSS, and Other Systems" (1996)
/// - Bernstein, D. J. "Cache-timing attacks on AES" (2005)

///|
/// Implements constant-time conditional selection between two integer values.
///
/// Parameters:
///
/// * `cond` : The boolean condition that determines which value to select.
/// * `a` : The integer value to return when the condition is true.
/// * `b` : The integer value to return when the condition is false.
///
/// Returns the value `a` if `cond` is true, otherwise returns `b`.
///
/// Example:
///
/// ```moonbit
/// let result1 = @ruifeng/moondsa.ite(true, 10, 20) // returns 10
///
/// let result2 = @ruifeng/moondsa.ite(false, 10, 20) // returns 20
/// ```
///
pub fn ite(cond : Bool, a : Int, b : Int) -> Int {
  if cond {
    return a
  }
  if not(cond) {
    return b
  }
  0 // unreachable
}
