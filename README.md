# PQNet

PQnet is a managed implementation of NIST Post-Quantum algorithms:
 * SLH-DSA (FIPS 205) implemented directly from NIST specification
 * ML-DSA (FIPS 204) ported to C# from Dilithium reference implementation

## Usage:
PQnet provides a simple API to generate keys, sign and verify messages. Both pure and "pre-hash" modes are supported and APIs accepting a context string are provided.

Getting started:

    using System.Security.Cryptography;
    using System.Text;
    
    using PQnet;
    using PQnet.ML_DSA;
    using PQnet.SLH_DSA;
    
    
    // Sample use of ML-DSA
    byte[] public_key;
    byte[] private_key;
    byte[] signature;
    byte[] message;
    bool authentic;
    
    message = Encoding.UTF8.GetBytes("Hello, World!");
    
    // Create ML-DSA object
    MlDsa44 mlDsa44 = new MlDsa44();
    
    // Generate key pair
    mlDsa44.GenerateKeyPair(out public_key, out private_key);
    
    // Sign message
    mlDsa44.Sign(message, private_key, out signature);
    
    // Verify signature
    authentic = mlDsa44.Verify(message, public_key, signature);
    
    
    // Sample "pre-hash" use of SLH-DSA:
    byte[] digest;
    
    // Create SLH-DSA object
    SlhDsaShake_256f slhDsaShake_256f = new SlhDsaShake_256f();
    slhDsaShake_256f.GenerateKeyPair(out public_key, out private_key);
    
    // Create message digest
    message = Encoding.UTF8.GetBytes("Hello, pre-hashed World!");
    digest = SHA256.HashData(message);
    
    // Sign message digest
    slhDsaShake_256f.SignHash(digest, private_key, PreHashFunction.SHA256, out signature);
    
    // Verify signature
    authentic = slhDsaShake_256f.VerifyHash(digest, public_key, PreHashFunction.SHA256, signature);

## Documentation
  API documentation can be found at 
  [Sandcastle/Documentation/Home.md](Sandcastle/Documentation/Home.md)

### All ACVP test vectors pass for:
  - ML-DSA 
  - SLH-DSA

## ToDo:
  - Create a .Net Framework version
  - Find/verify test vectors for pre-hash methods, those are as of yet untested
  - Add AVCP tests for Shake and SHA2
  - Use intrinsics to create AVX2 SHA2 version
  - Measure performance and optimize code
  - Maybe create NuGet package






