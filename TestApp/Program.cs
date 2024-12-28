﻿// See https://aka.ms/new-console-template for more information
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


// Sample "pre-hash" use:
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

Console.WriteLine($"Message is authentic: {authentic}");
