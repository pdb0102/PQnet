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

using PQnet.ML_DSA;
using PQnet.test.AVCP;

namespace PQnet.test {

	[TestClass]
	public sealed class MlDsaTests {
		[TestMethod]
		public void TestAvcpKeyGen() {
			AcvpMlDsaTestVectors<AcvpMlDsaKeyGenTestCase> test_vectors;
			MlDsaBase dilithium;
			MlDsa44 dilithium2;
			MlDsa65 dilithium3;
			MlDsa87 dilithium5;
			byte[] pk;
			byte[] sk;

			dilithium2 = new MlDsa44();
			dilithium3 = new MlDsa65();
			dilithium5 = new MlDsa87();

			test_vectors = AcvpMlDsa.LoadKeyGenVectors("ML_DSA.keyGen.prompt.json", "ML_DSA.keyGen.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpMlDsaTestGroup<AcvpMlDsaKeyGenTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpMlDsaKeyGenTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					// Perform the test
					switch (test_vectors.TestGroups[i].ParameterSet) {
						case "ML-DSA-44":
							dilithium = dilithium2;
							break;
						case "ML-DSA-65":
							dilithium = dilithium3;
							break;
						case "ML-DSA-87":
							dilithium = dilithium5;
							break;
						default:
							throw new NotImplementedException($"ParameterSet {test_vectors.TestGroups[i].ParameterSet} not supported");
					}

					dilithium.crypto_sign_keypair(out pk, out sk, seed: test_case.SeedBytes);
					CollectionAssert.AreEqual(test_case.PublicKeyBytes, pk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Public key mismatch");
					CollectionAssert.AreEqual(test_case.SecretKeyBytes, sk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Secret key mismatch");
				}
			}
		}

		[TestMethod]
		public void TestAvcpSigGen() {
			AcvpMlDsaTestVectors<AcvpMlDsaSigGenTestCase> test_vectors;
			MlDsaBase dilithium;
			MlDsa44 dilithium2;
			MlDsa65 dilithium3;
			MlDsa87 dilithium5;
			byte[] sig;
			byte[] null_rnd;

			dilithium2 = new MlDsa44();
			dilithium3 = new MlDsa65();
			dilithium5 = new MlDsa87();

			null_rnd = new byte[32];

			test_vectors = AcvpMlDsa.LoadSigGenVectors("ML_DSA.sigGen.prompt.json", "ML_DSA.sigGen.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpMlDsaTestGroup<AcvpMlDsaSigGenTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpMlDsaSigGenTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					// Perform the test
					switch (test_vectors.TestGroups[i].ParameterSet) {
						case "ML-DSA-44":
							dilithium = dilithium2;
							break;
						case "ML-DSA-65":
							dilithium = dilithium3;
							break;
						case "ML-DSA-87":
							dilithium = dilithium5;
							break;
						default:
							throw new NotImplementedException($"ParameterSet {test_vectors.TestGroups[i].ParameterSet} not supported");
					}

					dilithium.crypto_sign_signature_internal(out sig, test_case.MessageBytes, Array.Empty<byte>(), test_group.Deterministic ? null_rnd : test_case.RandomBytes, test_case.SecretKeyBytes);
					CollectionAssert.AreEqual(test_case.SignatureBytes, sig, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Signature mismatch");
				}
			}
		}

		[TestMethod]
		public void TestAvcpSigVer() {
			AcvpMlDsaTestVectors<AcvpMlDsaSigVerTestCase> test_vectors;
			MlDsaBase dilithium;
			MlDsa44 dilithium2;
			MlDsa65 dilithium3;
			MlDsa87 dilithium5;
			byte[] null_rnd;
			int ret;

			dilithium2 = new MlDsa44();
			dilithium3 = new MlDsa65();
			dilithium5 = new MlDsa87();

			null_rnd = new byte[32];


			test_vectors = AcvpMlDsa.LoadSigVerVectors("ML_DSA.sigVer.prompt.json", "ML_DSA.sigVer.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpMlDsaTestGroup<AcvpMlDsaSigVerTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpMlDsaSigVerTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					// Perform the test
					switch (test_vectors.TestGroups[i].ParameterSet) {
						case "ML-DSA-44":
							dilithium = dilithium2;
							break;
						case "ML-DSA-65":
							dilithium = dilithium3;
							break;
						case "ML-DSA-87":
							dilithium = dilithium5;
							break;
						default:
							throw new NotImplementedException($"ParameterSet {test_vectors.TestGroups[i].ParameterSet} not supported");
					}
					StringBuilder sb;

					sb = new StringBuilder();
					sb.Append($"uint8_t m[{test_case.MessageBytes.Length}] = {{");
					for (int x = 0; x < test_case.MessageBytes.Length; x++) {
						sb.Append("0x");
						sb.Append(test_case.MessageBytes[x].ToString("X2"));
						sb.Append(", ");
					}
					sb.Length -= 2;
					sb.AppendLine();

					sb.Append($"uint8_t pk[{test_group.PublicKeyBytes.Length}] = {{");
					for (int x = 0; x < test_group.PublicKeyBytes.Length; x++) {
						sb.Append("0x");
						sb.Append(test_group.PublicKeyBytes[x].ToString("X2"));
						sb.Append(", ");
					}
					sb.Length -= 2;
					sb.AppendLine();

					sb.Append($"uint8_t sig[{test_case.SignatureBytes.Length}] = {{");
					for (int x = 0; x < test_case.SignatureBytes.Length; x++) {
						sb.Append("0x");
						sb.Append(test_case.SignatureBytes[x].ToString("X2"));
						sb.Append(", ");
					}
					sb.Length -= 2;
					sb.AppendLine();

					ret = dilithium.crypto_sign_verify(test_case.SignatureBytes, test_case.MessageBytes, Array.Empty<byte>(), test_group.PublicKeyBytes);
					Assert.AreEqual(test_case.TestPassed, ret == 0, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Signature verification mismatch");
				}
			}
		}
	}
}