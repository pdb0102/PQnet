// See https://aka.ms/new-console-template for more information
using PQnet.ML_DSA;


// Sample use of ML-DSA
MlDsa44 mlDsa44;

mlDsa44 = new MlDsa44();
mlDsa44.GenerateKeyPair(out byte[] public_key, out byte[] private_key);
