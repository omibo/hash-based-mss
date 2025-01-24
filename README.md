# Hash-Based Signature Schemes

This project uses the [XMSS reference implementation](https://github.com/XMSS/xmss-reference) that accompanies [RFC 8391](https://tools.ietf.org/html/rfc8391) to implement PRF-based OTS (POTS).

## Added Implementation

### PRF-based One-Time Signature (POTS)
- A novel implementation of a one-time signature scheme based on pseudorandom functions/permutations.
- Implemented in `pots.c`


## Building and Running

### Dependencies
- OpenSSL (required for SHA-256 and SHA-512 hash functions)
  - macOS: `brew install openssl`

### Configuration
- Set `OPENSSL_PREFIX` in Makefile to your OpenSSL installation path
- macOS Homebrew installations are automatically detected

### Benchmarks
```bash
# Compare AES vs SHA performance
make benchmark/aes_hash

# Measure POTS performance (keygen, sign, verify)
make benchmark/pots

# Measure WOTS performance (keygen, sign, verify)
make benchmark/wots

# Clean built files
make clean
```

## License
This implementation extends the original XMSS reference code written by Andreas Hülsing and Joost Rijneveld. The original code and extensions are available under the CC0 1.0 Universal Public Domain Dedication.

## Note
This implementation is intended for research and experimentation. Production use requires careful consideration of deployment scenarios and threat models, particularly for stateful signature schemes.
