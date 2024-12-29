// MIT License
// 
// Copyright (c) 2024 Peter Dennis Bartok 
// 
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
// 
// The above copyright notice and this permission notice shall be included in all
// copies or substantial portions of the Software.
// 
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
// SOFTWARE.
//

using System.Text;

namespace PQnet.test {

	[TestClass]
	public sealed class PQApiRoundtripTests {
		[TestMethod]
		[DataRow("ML-DSA-44", DisplayName = "ML-DSA-44")]
		[DataRow("ML-DSA-65", DisplayName = "ML-DSA-65")]
		[DataRow("ML-DSA-87", DisplayName = "ML-DSA-87")]
		[DataRow("SLH-DSA-SHA2-128s", DisplayName = "SLH-DSA-SHA2-128s")]
		[DataRow("SLH-DSA-SHA2-128f", DisplayName = "SLH-DSA-SHA2-128f")]
		[DataRow("SLH-DSA-SHA2-192s", DisplayName = "SLH-DSA-SHA2-192s")]
		[DataRow("SLH-DSA-SHA2-192f", DisplayName = "SLH-DSA-SHA2-192f")]
		[DataRow("SLH-DSA-SHA2-256s", DisplayName = "SLH-DSA-SHA2-256s")]
		[DataRow("SLH-DSA-SHA2-256f", DisplayName = "SLH-DSA-SHA2-256f")]
		[DataRow("SLH-DSA-SHAKE-128s", DisplayName = "SLH-DSA-SHAKE-128s")]
		[DataRow("SLH-DSA-SHAKE-128f", DisplayName = "SLH-DSA-SHAKE-128f")]
		[DataRow("SLH-DSA-SHAKE-192s", DisplayName = "SLH-DSA-SHAKE-192s")]
		[DataRow("SLH-DSA-SHAKE-192f", DisplayName = "SLH-DSA-SHAKE-192f")]
		[DataRow("SLH-DSA-SHAKE-256s", DisplayName = "SLH-DSA-SHAKE-256s")]
		[DataRow("SLH-DSA-SHAKE-256f", DisplayName = "SLH-DSA-SHAKE-256f")]
		public void TestSignatureApi(string algorithm) {
			ISignature signature;
			byte[] private_key;
			byte[] public_key;
			byte[] signature_bytes;
			byte[] message;
			string error;
			bool success;

			message = Encoding.UTF8.GetBytes("Crichton was here");

			signature = PQC.GetSignatureAlgorithmInstance(algorithm);
			Assert.IsNotNull(signature, $"Failed to get instance of '{algorithm}' algorithm");
			Assert.AreEqual(algorithm, signature.Name, $"PQC.GetSignatureAlgorithmInstance returned wrong algorithm");

			success = signature.GenerateKeyPair(out public_key, out private_key, out error);
			Assert.IsTrue(success, $"Failed to generate key pair for '{algorithm}' algorithm: {error}");
			Assert.IsNull(error, $"Error was not null despite success [Error: {error}]");
			Assert.IsNotNull(public_key, $"Public key is null for '{algorithm}' algorithm");
			Assert.IsNotNull(private_key, $"Private key is null for '{algorithm}' algorithm");
			Assert.AreEqual(signature.PrivateKeyBytes, private_key.Length, $"Private key length is incorrect for '{algorithm}' algorithm");
			Assert.AreEqual(signature.PublicKeyBytes, public_key.Length, $"Public key length is incorrect for '{algorithm}' algorithm");

			success = signature.Sign(message, private_key, null, out signature_bytes, out error);
			Assert.IsTrue(success, $"Failed to sign message for '{algorithm}' algorithm: {error}");
			Assert.IsNull(error, $"Error was not null despite success [Error: {error}]");
			Assert.IsNotNull(signature_bytes, $"Signature is null for '{algorithm}' algorithm");
			Assert.AreEqual(signature.SignatureBytes, signature_bytes.Length, $"Signature length is incorrect for '{algorithm}' algorithm");

			success = signature.Verify(message, public_key, null, signature_bytes, out error);
			Assert.IsTrue(success, $"Failed to verify signature for '{algorithm}' algorithm: {error}");
			Assert.IsNull(error, $"Error was not null despite success [Error: {error}]");
		}

		[TestMethod]
		[DataRow("ML-KEM-512", DisplayName = "ML-KEM-512")]
		[DataRow("ML-KEM-768", DisplayName = "ML-KEM-768")]
		[DataRow("ML-KEM-1024", DisplayName = "ML-KEM-1024")]
		public void TestEncapsulationApi(string algorithm) {
			IEncapsulate encapsulate;
			byte[] private_key;
			byte[] public_key;
			byte[] shared_secret_key;
			byte[] decapsulated_shared_secret_key;
			byte[] ciphertext;
			string error;
			bool success;

			encapsulate = PQC.GetEncapsulationAlgorithmInstance(algorithm);
			Assert.IsNotNull(encapsulate, $"Failed to get instance of '{algorithm}' algorithm");
			Assert.AreEqual(algorithm, encapsulate.Name, $"PQC.GetEncapsulationAlgorithmInstance returned wrong algorithm");

			success = encapsulate.GenerateKeyPair(out public_key, out private_key, out error);
			Assert.IsTrue(success, $"Failed to generate key pair for '{algorithm}' algorithm: {error}");
			Assert.IsNull(error, $"Error was not null despite success [Error: {error}]");
			Assert.IsNotNull(public_key, $"Public key is null for '{algorithm}' algorithm");
			Assert.IsNotNull(private_key, $"Private key is null for '{algorithm}' algorithm");
			Assert.AreEqual(encapsulate.PrivateKeyBytes, private_key.Length, $"Private key length is incorrect for '{algorithm}' algorithm");
			Assert.AreEqual(encapsulate.PublicKeyBytes, public_key.Length, $"Public key length is incorrect for '{algorithm}' algorithm");

			success = encapsulate.Encapsulate(public_key, out shared_secret_key, out ciphertext, out error);
			Assert.IsTrue(success, $"Failed to encapsulate for '{algorithm}' algorithm: {error}");
			Assert.IsNull(error, $"Error was not null despite success [Error: {error}]");
			Assert.IsNotNull(shared_secret_key, $"Shared secret key is null for '{algorithm}' algorithm");
			Assert.IsNotNull(ciphertext, $"Ciphertext is null for '{algorithm}' algorithm");
			Assert.AreEqual(encapsulate.CiphertextBytes, ciphertext.Length, $"Ciphertext length is incorrect for '{algorithm}' algorithm");

			success = encapsulate.Decapsulate(private_key, ciphertext, out decapsulated_shared_secret_key, out error);
			Assert.IsTrue(success, $"Failed to decapsulate for '{algorithm}' algorithm: {error}");
			Assert.IsNull(error, $"Error was not null despite success [Error: {error}]");
			Assert.IsNotNull(decapsulated_shared_secret_key, $"Decapsulated Shared secret key is null for '{algorithm}' algorithm");

			Assert.AreEqual(shared_secret_key.Length, decapsulated_shared_secret_key.Length, $"Decapsulated shared secret key length does not match encapsulated shared secret length for '{algorithm}' algorithm");
			CollectionAssert.AreEqual(shared_secret_key, decapsulated_shared_secret_key, $"Shared secret key does not match decapsulated shared secret key for '{algorithm}' algorithm");
		}
	}
}