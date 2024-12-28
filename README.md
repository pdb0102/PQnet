# PQNet
Managed implementation of Post-Quantum algorithms
  - SLH-DSA implemented from FIPS 205 spec
  - ML-DSA ported to C# from Dilithium reference implementation

## All ACVP test vectors pass for:
  - ML-DSA 
  - SLH-DSA

## ToDo:
  - Add AVCP tests for Shake and SHA2
  - Use intrinsics to create AVX2 SHA2 version
  - Measure performance and optimize code

## Usage:
  - See PQC class
    _todo:_
    example SLH keygen: PQC.SlhDsaShake_192f.slh_keygen()





