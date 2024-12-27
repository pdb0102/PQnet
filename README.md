# PQNet
Managed implementation of Post-Quantum algorithms

**Work-in-progress - DO NOT USE YET**

  - SLH-DSA implemented from FIPS 205 spec
  - ML-DSA ported to C# from Dilithium reference implementation

## Working against AVCP Vectors:
  - ML-DSA Key Generation
  - ML-DSA Signature Generation
  - SLH-DSA-SHAKE Key Generation
  - SLH-DSA-SHAKE Signature Generation

## Issues:
  - ML-DSA Signature Verification fails
  - SLH-DSA SHA2 fails
  - SLH-DSA Signature Verification fails

## ToDo:
  - Add AVCP tests for Shake and SHA2
  - Use intrinsics to create AVX2 SHA2 version
  - Measure performance and optimize code

## Usage:
  - See PQC class
    _todo:_
    example SLH keygen: PQC.SlhDsaShake_192f.slh_keygen()





