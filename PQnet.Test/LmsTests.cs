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

using System;
using System.Text;

namespace PQnet.test {
	/// <summary>
	/// Tests for low-level LMS (RFC 8554) implementation
	/// </summary>
	[TestClass]
	public sealed class LmsTests {
		[TestMethod]
		public void TestLmsSha256M32H5_BasicRoundtrip() {
			LmsSha256M32H5 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] message;
			byte[] signature;
			byte[] updated_private_key;
			bool is_valid;

			lms = new LmsSha256M32H5();
			message = Encoding.UTF8.GetBytes("Hello, LMS!");

			// Generate key pair
			lms.GenerateKeyPair(out public_key, out private_key);

			Assert.IsNotNull(public_key, "Public key should not be null");
			Assert.IsNotNull(private_key, "Private key should not be null");
			Assert.AreEqual(lms.PublicKeyBytes, public_key.Length, "Public key size mismatch");
			Assert.AreEqual(lms.PrivateKeyBytes, private_key.Length, "Private key size mismatch");

			// Sign message
			signature = lms.Sign(private_key, message, out updated_private_key);

			Assert.IsNotNull(signature, "Signature should not be null");
			Assert.AreEqual(lms.SignatureBytes, signature.Length, "Signature size mismatch");
			Assert.IsNotNull(updated_private_key, "Updated private key should not be null");

			// Verify signature
			is_valid = lms.Verify(public_key, signature, message);
			Assert.IsTrue(is_valid, "Signature verification should succeed");
		}

		[TestMethod]
		public void TestLmsSha256M32H10_BasicRoundtrip() {
			LmsSha256M32H10 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] message;
			byte[] signature;
			byte[] updated_private_key;
			bool is_valid;

			lms = new LmsSha256M32H10();
			message = Encoding.UTF8.GetBytes("Testing LMS H10");

			lms.GenerateKeyPair(out public_key, out private_key);
			signature = lms.Sign(private_key, message, out updated_private_key);
			is_valid = lms.Verify(public_key, signature, message);

			Assert.IsTrue(is_valid, "Signature verification should succeed for H10");
		}

		[TestMethod]
		public void TestLmsSha256M32H15_BasicRoundtrip() {
			LmsSha256M32H15 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] message;
			byte[] signature;
			byte[] updated_private_key;
			bool is_valid;

			lms = new LmsSha256M32H15();
			message = Encoding.UTF8.GetBytes("Testing LMS H15");

			lms.GenerateKeyPair(out public_key, out private_key);
			signature = lms.Sign(private_key, message, out updated_private_key);
			is_valid = lms.Verify(public_key, signature, message);

			Assert.IsTrue(is_valid, "Signature verification should succeed for H15");
		}

		[TestMethod]
		public void TestLmsSha256M32H20_BasicRoundtrip() {
			LmsSha256M32H20 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] message;
			byte[] signature;
			byte[] updated_private_key;
			bool is_valid;

			lms = new LmsSha256M32H20();
			message = Encoding.UTF8.GetBytes("Testing LMS H20");

			lms.GenerateKeyPair(out public_key, out private_key);
			signature = lms.Sign(private_key, message, out updated_private_key);
			is_valid = lms.Verify(public_key, signature, message);

			Assert.IsTrue(is_valid, "Signature verification should succeed for H20");
		}

		[TestMethod]
		public void TestMultipleSignatures() {
			LmsSha256M32H5 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] message1;
			byte[] message2;
			byte[] message3;
			byte[] signature1;
			byte[] signature2;
			byte[] signature3;
			byte[] updated_private_key;
			bool is_valid;

			lms = new LmsSha256M32H5();
			message1 = Encoding.UTF8.GetBytes("First message");
			message2 = Encoding.UTF8.GetBytes("Second message");
			message3 = Encoding.UTF8.GetBytes("Third message");

			lms.GenerateKeyPair(out public_key, out private_key);

			// First signature
			signature1 = lms.Sign(private_key, message1, out updated_private_key);
			is_valid = lms.Verify(public_key, signature1, message1);
			Assert.IsTrue(is_valid, "First signature should be valid");

			// Second signature (use updated key)
			signature2 = lms.Sign(updated_private_key, message2, out updated_private_key);
			is_valid = lms.Verify(public_key, signature2, message2);
			Assert.IsTrue(is_valid, "Second signature should be valid");

			// Third signature (use updated key again)
			signature3 = lms.Sign(updated_private_key, message3, out updated_private_key);
			is_valid = lms.Verify(public_key, signature3, message3);
			Assert.IsTrue(is_valid, "Third signature should be valid");

			// All three signatures should still be independently valid
			is_valid = lms.Verify(public_key, signature1, message1);
			Assert.IsTrue(is_valid, "First signature should still be valid");

			is_valid = lms.Verify(public_key, signature2, message2);
			Assert.IsTrue(is_valid, "Second signature should still be valid");
		}

		[TestMethod]
		public void TestInvalidSignatureDetection() {
			LmsSha256M32H5 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] message;
			byte[] wrong_message;
			byte[] signature;
			byte[] updated_private_key;
			byte[] corrupted_signature;
			bool is_valid;

			lms = new LmsSha256M32H5();
			message = Encoding.UTF8.GetBytes("Correct message");
			wrong_message = Encoding.UTF8.GetBytes("Wrong message");

			lms.GenerateKeyPair(out public_key, out private_key);
			signature = lms.Sign(private_key, message, out updated_private_key);

			// Verify with wrong message should fail
			is_valid = lms.Verify(public_key, signature, wrong_message);
			Assert.IsFalse(is_valid, "Signature verification should fail with wrong message");

			// Corrupt the signature
			corrupted_signature = new byte[signature.Length];
			Array.Copy(signature, corrupted_signature, signature.Length);
			corrupted_signature[10] ^= 0xFF; // Flip bits in the signature

			// Verify corrupted signature should fail
			is_valid = lms.Verify(public_key, corrupted_signature, message);
			Assert.IsFalse(is_valid, "Signature verification should fail with corrupted signature");
		}

		[TestMethod]
		public void TestSignatureCountTracking() {
			LmsSha256M32H5 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] message;
			byte[] signature;
			byte[] updated_private_key;
			uint count;

			lms = new LmsSha256M32H5();
			message = Encoding.UTF8.GetBytes("Message");

			lms.GenerateKeyPair(out public_key, out private_key);

			// Initial count should be 0
			count = lms.GetSignatureCount(private_key);
			Assert.AreEqual(0u, count, "Initial signature count should be 0");

			// After first signature
			signature = lms.Sign(private_key, message, out updated_private_key);
			count = lms.GetSignatureCount(updated_private_key);
			Assert.AreEqual(1u, count, "Signature count should be 1 after first signature");

			// After second signature
			signature = lms.Sign(updated_private_key, message, out updated_private_key);
			count = lms.GetSignatureCount(updated_private_key);
			Assert.AreEqual(2u, count, "Signature count should be 2 after second signature");

			// After third signature
			signature = lms.Sign(updated_private_key, message, out updated_private_key);
			count = lms.GetSignatureCount(updated_private_key);
			Assert.AreEqual(3u, count, "Signature count should be 3 after third signature");
		}

		[TestMethod]
		public void TestKeyExhaustion() {
			LmsSha256M32H5 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] message;
			byte[] signature;
			byte[] updated_private_key;
			bool is_exhausted;
			int max_signatures;
			int i;

			lms = new LmsSha256M32H5();
			message = Encoding.UTF8.GetBytes("Message");
			max_signatures = lms.MaxSignatures;

			Assert.AreEqual(32, max_signatures, "H5 should support 32 signatures");

			lms.GenerateKeyPair(out public_key, out private_key);

			// Should not be exhausted initially
			is_exhausted = lms.IsExhausted(private_key);
			Assert.IsFalse(is_exhausted, "Key should not be exhausted initially");

			updated_private_key = private_key;

			// Use all available signatures
			for (i = 0; i < max_signatures; i++) {
				signature = lms.Sign(updated_private_key, message, out updated_private_key);
				Assert.IsNotNull(signature, $"Signature {i} should be generated successfully");
			}

			// Now key should be exhausted
			is_exhausted = lms.IsExhausted(updated_private_key);
			Assert.IsTrue(is_exhausted, "Key should be exhausted after all signatures used");

			// Trying to sign again should throw an exception
			Assert.ThrowsException<InvalidOperationException>(() => {
				lms.Sign(updated_private_key, message, out updated_private_key);
			}, "Signing with exhausted key should throw InvalidOperationException");
		}

		[TestMethod]
		public void TestDeterministicKeyGeneration() {
			LmsSha256M32H5 lms;
			byte[] I1;
			byte[] SEED1;
			byte[] public_key1;
			byte[] private_key1;
			byte[] public_key2;
			byte[] private_key2;
			int i;

			lms = new LmsSha256M32H5();

			// Use fixed I and SEED
			I1 = new byte[16];
			SEED1 = new byte[32];
			for (i = 0; i < 16; i++) {
				I1[i] = (byte)i;
			}
			for (i = 0; i < 32; i++) {
				SEED1[i] = (byte)(i * 2);
			}

			// Generate key pair twice with same I and SEED
			lms.GenerateKeyPair(I1, SEED1, out public_key1, out private_key1);
			lms.GenerateKeyPair(I1, SEED1, out public_key2, out private_key2);

			// Keys should be identical
			Assert.AreEqual(public_key1.Length, public_key2.Length, "Public key lengths should match");
			Assert.AreEqual(private_key1.Length, private_key2.Length, "Private key lengths should match");

			for (i = 0; i < public_key1.Length; i++) {
				Assert.AreEqual(public_key1[i], public_key2[i], $"Public key byte {i} should match");
			}

			for (i = 0; i < private_key1.Length; i++) {
				Assert.AreEqual(private_key1[i], private_key2[i], $"Private key byte {i} should match");
			}
		}

		[TestMethod]
		public void TestDifferentParameterSets() {
			LmsSha256M32H5 lms_h5;
			LmsSha256M32H10 lms_h10;
			LmsSha256M32H15 lms_h15;
			LmsSha256M32H20 lms_h20;

			lms_h5 = new LmsSha256M32H5();
			lms_h10 = new LmsSha256M32H10();
			lms_h15 = new LmsSha256M32H15();
			lms_h20 = new LmsSha256M32H20();

			// Verify tree heights
			Assert.AreEqual(5, lms_h5.TreeHeight, "H5 tree height should be 5");
			Assert.AreEqual(10, lms_h10.TreeHeight, "H10 tree height should be 10");
			Assert.AreEqual(15, lms_h15.TreeHeight, "H15 tree height should be 15");
			Assert.AreEqual(20, lms_h20.TreeHeight, "H20 tree height should be 20");

			// Verify max signatures
			Assert.AreEqual(32, lms_h5.MaxSignatures, "H5 should support 32 signatures");
			Assert.AreEqual(1024, lms_h10.MaxSignatures, "H10 should support 1024 signatures");
			Assert.AreEqual(32768, lms_h15.MaxSignatures, "H15 should support 32768 signatures");
			Assert.AreEqual(1048576, lms_h20.MaxSignatures, "H20 should support 1048576 signatures");

			// Verify names
			Assert.AreEqual("LMS-SHA256-M32-H5", lms_h5.Name, "H5 name should be correct");
			Assert.AreEqual("LMS-SHA256-M32-H10", lms_h10.Name, "H10 name should be correct");
			Assert.AreEqual("LMS-SHA256-M32-H15", lms_h15.Name, "H15 name should be correct");
			Assert.AreEqual("LMS-SHA256-M32-H20", lms_h20.Name, "H20 name should be correct");
		}

		[TestMethod]
		public void TestEmptyMessage() {
			LmsSha256M32H5 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] empty_message;
			byte[] signature;
			byte[] updated_private_key;
			bool is_valid;

			lms = new LmsSha256M32H5();
			empty_message = new byte[0];

			lms.GenerateKeyPair(out public_key, out private_key);
			signature = lms.Sign(private_key, empty_message, out updated_private_key);
			is_valid = lms.Verify(public_key, signature, empty_message);

			Assert.IsTrue(is_valid, "Signature verification should succeed for empty message");
		}

		[TestMethod]
		public void TestLargeMessage() {
			LmsSha256M32H5 lms;
			byte[] public_key;
			byte[] private_key;
			byte[] large_message;
			byte[] signature;
			byte[] updated_private_key;
			bool is_valid;
			int i;

			lms = new LmsSha256M32H5();

			// Create a large message (10 KB)
			large_message = new byte[10240];
			for (i = 0; i < large_message.Length; i++) {
				large_message[i] = (byte)(i % 256);
			}

			lms.GenerateKeyPair(out public_key, out private_key);
			signature = lms.Sign(private_key, large_message, out updated_private_key);
			is_valid = lms.Verify(public_key, signature, large_message);

			Assert.IsTrue(is_valid, "Signature verification should succeed for large message");
		}

		[TestMethod]
		public void TestCrossParameterSetIncompatibility() {
			LmsSha256M32H5 lms_h5;
			LmsSha256M32H10 lms_h10;
			byte[] public_key_h5;
			byte[] private_key_h5;
			byte[] public_key_h10;
			byte[] private_key_h10;
			byte[] message;
			byte[] signature_h5;
			byte[] signature_h10;
			byte[] updated_private_key;
			bool is_valid;

			lms_h5 = new LmsSha256M32H5();
			lms_h10 = new LmsSha256M32H10();
			message = Encoding.UTF8.GetBytes("Test message");

			lms_h5.GenerateKeyPair(out public_key_h5, out private_key_h5);
			lms_h10.GenerateKeyPair(out public_key_h10, out private_key_h10);

			signature_h5 = lms_h5.Sign(private_key_h5, message, out updated_private_key);
			signature_h10 = lms_h10.Sign(private_key_h10, message, out updated_private_key);

			// H5 signature should not verify with H10 public key
			is_valid = lms_h10.Verify(public_key_h10, signature_h5, message);
			Assert.IsFalse(is_valid, "H5 signature should not verify with H10 public key");

			// H10 signature should not verify with H5 public key
			is_valid = lms_h5.Verify(public_key_h5, signature_h10, message);
			Assert.IsFalse(is_valid, "H10 signature should not verify with H5 public key");
		}
	}
}
