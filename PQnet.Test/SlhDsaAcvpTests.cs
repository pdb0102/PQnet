﻿// MIT License
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

using System.Diagnostics;

using PQnet.test.AVCP;

namespace PQnet.test {

	[TestClass]
	public sealed class SlhDsaAcvpTests {
		[TestMethod]
		public void TestAvcpKeyGen() {
			AcvpSlhDsaTestVectors<AcvpSlhDsaKeyGenTestCase> test_vectors;
			SlhDsaBase slh_dsa;
			byte[] pk;
			byte[] sk;

			test_vectors = AcvpSlhDsa.LoadKeyGenVectors("SLH_DSA.keyGen.prompt.json", "SLH_DSA.keyGen.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpSlhDsaTestGroup<AcvpSlhDsaKeyGenTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpSlhDsaKeyGenTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					slh_dsa = GetAlgorithm(test_vectors.TestGroups[i].ParameterSet, true);

					(sk, pk) = slh_dsa.slh_keygen_internal(test_case.SkSeedBytes, test_case.SkPrfBytes, test_case.PkSeedBytes);
					CollectionAssert.AreEqual(test_case.PublicKeyBytes, pk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Public key mismatch");
					CollectionAssert.AreEqual(test_case.SecretKeyBytes, sk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Secret key mismatch");
					Debug.WriteLine($"Passed - TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Parameter Set: {test_vectors.TestGroups[i].ParameterSet}");
				}
			}
		}

		[TestMethod]
		public void TestAvcpSigGen() {
			AcvpSlhDsaTestVectors<AcvpSlhDsaSigGenTestCase> test_vectors;
			SlhDsaBase slh_dsa;
			byte[] sig;
			byte[] null_rnd;

			null_rnd = new byte[32];

			test_vectors = AcvpSlhDsa.LoadSigGenVectors("SLH_DSA.sigGen.prompt.json", "SLH_DSA.sigGen.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpSlhDsaTestGroup<AcvpSlhDsaSigGenTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpSlhDsaSigGenTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					slh_dsa = GetAlgorithm(test_vectors.TestGroups[i].ParameterSet, test_group.Deterministic);

					try {
						if (test_group.PreHash != "preHash") {
							if (test_group.SignatureInterface != "external") {
								sig = slh_dsa.slh_sign_internal(test_case.MessageBytes, test_case.SecretKeyBytes, test_group.Deterministic ? null : test_case.RandomBytes);
							} else {
								sig = slh_dsa.slh_sign(test_case.MessageBytes, test_case.ContextBytes, test_case.SecretKeyBytes, test_group.Deterministic ? null : test_case.RandomBytes);
							}
						} else {
							PreHashFunction pre_hash_function;

							pre_hash_function = GetHashFunction(test_case.HashAlg);
							sig = slh_dsa.hash_slh_sign(test_case.MessageBytes, test_case.ContextBytes, pre_hash_function, test_case.SecretKeyBytes, test_group.Deterministic ? null : test_case.RandomBytes);
						}
					} catch (NotImplementedException ex) {
						Debug.WriteLine($"TestGroup {test_group.TgId}, TestCase {test_case.TcId}; Not implemented: {ex.Message}");
						continue;
					}
					CollectionAssert.AreEqual(test_case.SignatureBytes, sig, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: [PH: {test_group.PreHash}, IF: {test_group.SignatureInterface}] Signature mismatch");
					Debug.WriteLine($"Passed - TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Parameter Set: {test_vectors.TestGroups[i].ParameterSet}");
				}
			}
		}

		[TestMethod]
		public void TestAvcpSigVer() {
			AcvpSlhDsaTestVectors<AcvpSlhDsaSigVerTestCase> test_vectors;
			SlhDsaBase slh_dsa;
			byte[] null_rnd;
			bool result;

			null_rnd = new byte[32];

			test_vectors = AcvpSlhDsa.LoadSigVerVectors("SLH_DSA.sigVer.prompt.json", "SLH_DSA.sigVer.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpSlhDsaTestGroup<AcvpSlhDsaSigVerTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpSlhDsaSigVerTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					slh_dsa = GetAlgorithm(test_vectors.TestGroups[i].ParameterSet, true);

					try {
						if (test_group.PreHash != "preHash") {
							if (test_group.SignatureInterface != "external") {
								result = slh_dsa.slh_verify_internal(test_case.MessageBytes, test_case.SignatureBytes, test_case.PublicKeyBytes);
							} else {
								result = slh_dsa.slh_verify(test_case.MessageBytes, test_case.SignatureBytes, test_case.ContextBytes, test_case.PublicKeyBytes);
							}
						} else {
							PreHashFunction pre_hash_function;

							pre_hash_function = GetHashFunction(test_case.HashAlg);
							result = slh_dsa.hash_slh_verify(test_case.MessageBytes, test_case.SignatureBytes, test_case.ContextBytes, pre_hash_function, test_case.PublicKeyBytes);
						}
					} catch (NotImplementedException ex) {
						Debug.WriteLine($"TestGroup {test_group.TgId}, TestCase {test_case.TcId}; Not implemented: {ex.Message}");
						continue;
					}

					Assert.AreEqual(test_case.TestPassed, result, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Signature verification mismatch");
					if (test_case.TestPassed != result) {
						Debug.WriteLine($"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: [PH: {test_group.PreHash}, IF: {test_group.SignatureInterface}, Hash: {test_case.HashAlg}] Signature verification mismatch expected {test_case.TestPassed} != {result}");
					} else
						Debug.WriteLine($"Passed - TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Parameter Set: {test_vectors.TestGroups[i].ParameterSet} Signature verification as expected {test_case.TestPassed}");
				}
			}
		}


		[TestMethod]
		[DataRow("SLH-DSA-SHA2-128s")]
		[DataRow("SLH-DSA-SHA2-128f")]
		[DataRow("SLH-DSA-SHA2-192s")]
		[DataRow("SLH-DSA-SHA2-192f")]
		[DataRow("SLH-DSA-SHA2-256s")]
		[DataRow("SLH-DSA-SHA2-256f")]
		[DataRow("SLH-DSA-SHAKE-128s")]
		[DataRow("SLH-DSA-SHAKE-128f")]
		[DataRow("SLH-DSA-SHAKE-192s")]
		[DataRow("SLH-DSA-SHAKE-192f")]
		[DataRow("SLH-DSA-SHAKE-256s")]
		[DataRow("SLH-DSA-SHAKE-256f")]
		public void TestPublicKeyExtraction(string parameter_set) {
			SlhDsaBase slhdsa;
			byte[] private_key;
			byte[] public_key;
			byte[] derived_public_key;
			string error;
			bool success;

			slhdsa = GetAlgorithm(parameter_set, false);
			success = slhdsa.GenerateKeyPair(out public_key, out private_key, out error);
			Assert.IsTrue(success, $"Key generation failed for {parameter_set}; {error}");

			success = slhdsa.DerivePublicFromPrivateKey(private_key, out derived_public_key, out _);
			Assert.IsTrue(success, $"Public key derivation failed for {parameter_set}; {error}");

			CollectionAssert.AreEqual(public_key, derived_public_key, $"Derive public key mismatch for {parameter_set}");
		}

		private SlhDsaBase GetAlgorithm(string parameter_set, bool deterministic) {
			switch (parameter_set) {
				case "SLH-DSA-SHA2-128s":
					return new SlhDsaSha2_128s(deterministic);
				case "SLH-DSA-SHA2-128f":
					return new SlhDsaSha2_128f(deterministic);
				case "SLH-DSA-SHA2-192s":
					return new SlhDsaSha2_192s(deterministic);
				case "SLH-DSA-SHA2-192f":
					return new SlhDsaSha2_192f(deterministic);
				case "SLH-DSA-SHA2-256s":
					return new SlhDsaSha2_256s(deterministic);
				case "SLH-DSA-SHA2-256f":
					return new SlhDsaSha2_256f(deterministic);
				case "SLH-DSA-SHAKE-128s":
					return new SlhDsaShake_128s(deterministic);
				case "SLH-DSA-SHAKE-128f":
					return new SlhDsaShake_128f(deterministic);
				case "SLH-DSA-SHAKE-192s":
					return new SlhDsaShake_192s(deterministic);
				case "SLH-DSA-SHAKE-192f":
					return new SlhDsaShake_192f(deterministic);
				case "SLH-DSA-SHAKE-256s":
					return new SlhDsaShake_256s(deterministic);
				case "SLH-DSA-SHAKE-256f":
					return new SlhDsaShake_256f(deterministic);

				default:
					throw new NotImplementedException($"ParameterSet {parameter_set} not supported");
			}
		}

		private PreHashFunction GetHashFunction(string hash_alg) {
			switch (hash_alg) {
				case "SHA2-224":
					return PreHashFunction.SHA224;
				case "SHA2-256":
					return PreHashFunction.SHA256;
				case "SHA2-384":
					return PreHashFunction.SHA384;
				case "SHA2-512":
					return PreHashFunction.SHA512;
				case "SHA3-224":
					return PreHashFunction.SHA3_224;
				case "SHA3-256":
					return PreHashFunction.SHA3_256;
				case "SHA3-384":
					return PreHashFunction.SHA3_384;
				case "SHA3-512":
					return PreHashFunction.SHA3_512;
				case "SHA2-512/224":
					return PreHashFunction.SHA512_224;
				case "SHA2-512/256":
					return PreHashFunction.SHA512_256;
				case "SHAKE-128":
					return PreHashFunction.SHAKE128;
				case "SHAKE-256":
					return PreHashFunction.SHAKE256;
				default:
					throw new Exception($"Unsupported hash algorithm {hash_alg}");
			}
		}
	}
}