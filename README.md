# ruifeng/dilithium

A MoonBit implementation of the Dilithium post-quantum digital signature algorithm. This library provides key generation, signing, and verification functions for the Dilithium signature scheme, which is designed to be secure against attacks by quantum computers.

## Features

- **Complete Dilithium Implementation**: Full implementation of the Dilithium signature scheme as specified in the NIST post-quantum cryptography standard
- **Multiple Security Levels**: Support for all three security levels:
  - Dilithium-2 (NIST security level 2)
  - Dilithium-3 (NIST security level 3) 
  - Dilithium-5 (NIST security level 5)
- **Deterministic & Non-deterministic Signing**: Support for both deterministic and randomized signature generation
- **Comprehensive Testing**: Extensive Known Answer Tests (KAT) validation against official test vectors
- **Memory Safe**: Written in MoonBit with memory safety guarantees

## Security Warning

⚠️ **Security Notice**: This implementation has not undergone formal security analysis or side-channel resistance evaluation. While it implements the correct algorithms, it should not be used in production systems without additional security review and hardening.

## Installation

Add this package to your MoonBit project:

```bash
moon add ruifeng/moondsa
```

## Quick Start

### Basic Usage

```moonbit
// Import the package
let @dilithium = @ruifeng/moondsa

// Set security level (Dilithium3 is the default)
@dilithium.dilithium_context.set_level(SecurityLevel::Dilithium3)

// Generate key pair with random seed
let (pk, sk) = @dilithium.crypto_sign_keypair(Err(@random.Rand::new()))

// Sign a message
let message = "Hello, post-quantum world!".to_bytes()
let signature = @dilithium.crypto_sign_signature(message, sk)

// Verify signature
let result = @dilithium.crypto_sign_verify(signature, message, pk)
match result {
  Ok(_) => println("Signature is valid!")
  Err(e) => println("Signature verification failed: \(e)")
}
```

### Deterministic Key Generation

```moonbit
// Generate keys from a specific seed (deterministic)
let seed = Array::make(32, 0x42) // 32-byte seed
let (pk, sk) = @dilithium.crypto_sign_keypair(Ok(seed))
```

### Security Level Selection

```moonbit
// Available security levels
@dilithium.dilithium_context.set_level(SecurityLevel::Dilithium2)  // 128-bit security
@dilithium.dilithium_context.set_level(SecurityLevel::Dilithium3)  // 192-bit security  
@dilithium.dilithium_context.set_level(SecurityLevel::Dilithium5)  // 256-bit security
```

## API Reference

### Core Functions

- `crypto_sign_keypair(seed)`: Generate public/private key pair
- `crypto_sign_signature(message, secret_key)`: Sign a message
- `crypto_sign_verify(signature, message, public_key)`: Verify a signature

### Configuration

- `SecurityLevel`: Enum with variants `Dilithium2`, `Dilithium3`, `Dilithium5`
- `dilithium_context`: Global configuration context

## Algorithm Details

Dilithium is a lattice-based digital signature scheme based on the hardness of the Module Learning With Errors (MLWE) problem. The implementation follows the NIST FIPS 204 standard specification.

### Key Sizes

| Security Level | Public Key | Secret Key | Signature |
|----------------|------------|------------|-----------|
| Dilithium-2    | 1312 bytes | 2528 bytes | 2420 bytes |
| Dilithium-3    | 1952 bytes | 4016 bytes | 3293 bytes |
| Dilithium-5    | 2592 bytes | 4864 bytes | 4595 bytes |

## Testing

The implementation includes comprehensive Known Answer Tests (KAT) that validate against the official NIST test vectors:

```bash
# Run all tests
moon test

# Run with verbose output
moon test -v
```

## Roadmap

- [x] Basic functionality: keygen, sign, verify
- [x] Multiple security levels: Dilithium-2, Dilithium-3, Dilithium-5
- [x] Comprehensive KAT testing
- [ ] AES-based signature algorithm variant
- [ ] Enhanced non-deterministic algorithms
- [ ] Side-channel resistance improvements
- [ ] Formal security analysis

## References

- [NIST FIPS 204: Module-Lattice-Based Digital Signature Standard](https://csrc.nist.gov/pubs/fips/204/final)
- [Dilithium Algorithm Specification and Supporting Documentation](https://pq-crystals.org/dilithium/data/dilithium-specification-round3-20210208.pdf)
- [Argyle-Software Dilithium Implementation](https://github.com/Argyle-Software/dilithium/)
- [Cryptography 101 - Post-Quantum Cryptography](https://cryptography101.ca/)

## License

Licensed under the Apache License 2.0. See [LICENSE](LICENSE) for details.