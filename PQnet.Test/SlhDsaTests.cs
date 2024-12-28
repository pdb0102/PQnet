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

using System.Diagnostics;

using PQnet.SLH_DSA;
using PQnet.test.AVCP;

namespace PQnet.test {

	[TestClass]
	public sealed class SlhDsa {
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
					if (slh_dsa.Name.Contains("SHA2")) {
						continue;
					}

					(sk, pk) = slh_dsa.slh_keygen_internal(test_case.SkSeedBytes, test_case.SkPrfBytes, test_case.PkSeedBytes);
					CollectionAssert.AreEqual(test_case.PublicKeyBytes, pk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Public key mismatch");
					CollectionAssert.AreEqual(test_case.SecretKeyBytes, sk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Secret key mismatch");
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
					if (slh_dsa.Name.Contains("SHA2")) {
						continue;
					}

					sig = slh_dsa.slh_sign_internal(test_case.MessageBytes, test_case.SecretKeyBytes, test_group.Deterministic ? null : test_case.RandomBytes);
					CollectionAssert.AreEqual(test_case.SignatureBytes, sig, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Signature mismatch");
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
					if (slh_dsa.Name.Contains("SHA2")) {
						continue;
					}

					result = slh_dsa.slh_verify_internal(test_case.MessageBytes, test_case.SignatureBytes, test_case.PublicKeyBytes);
					Assert.AreEqual(test_case.TestPassed, result, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Signature verification mismatch");
					Console.WriteLine($"Passed - TestGroup {test_group.TgId}, TestCase {test_case.TcId}: Parameter Set: {test_vectors.TestGroups[i].ParameterSet}");
				}
			}
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
	}
}