# PQnet

PQnet is a managed implementation of NIST Post-Quantum algorithms:
 * ML-KEM (FIPS 203) ported to C# from Kyber reference implementation
 * ML-DSA (FIPS 204) ported to C# from Dilithium reference implementation
 * SLH-DSA (FIPS 205) implemented directly from NIST specification

## Usage:
PQnet provides a simple API to generate keys, sign and verify messages, and to encapsulate/decapsulate keys. 
For signature algorithms, both pure and "pre-hash" modes are supported and APIs accepting a context string are provided.

Getting started:

    using System.Security.Cryptography;
    using System.Text;
    
    using PQnet;
    
    byte[] public_key;
    byte[] private_key;
    byte[] signature;
    byte[] message;
    bool authentic;
    
    message = Encoding.UTF8.GetBytes("Hello, World!");
    
    // Sample signing with ML-DSA-44
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

      
    // Share a key
    MlKem1024 mlKem1024 = new MlKem1024();
    byte[] shared_secret_key;
    byte[] ciphertext;
    
    mlKem1024.GenerateKeyPair(out public_key, out private_key);
    mlKem1024.Encapsulate(public_key, out shared_secret_key, out ciphertext);
    
    // Decapsulate the shared secret key
    byte[] decapsulated_shared_secret_key;
    mlKem1024.Decapsulate(private_key, ciphertext, out decapsulated_shared_secret_key);
 

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






