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

using PQnet.test.AVCP;

namespace PQnet.test {

	[TestClass]
	public sealed class MlDsaTests {
		[TestMethod]
		public void TestAvcpKeyGen() {
			AcvpMlDsaTestVectors<AcvpMlDsaKeyGenTestCase> test_vectors;
			MlDsaBase mldsa;
			byte[] pk;
			byte[] sk;

			test_vectors = AcvpMlDsa.LoadKeyGenVectors("ML_DSA.keyGen.prompt.json", "ML_DSA.keyGen.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpMlDsaTestGroup<AcvpMlDsaKeyGenTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpMlDsaKeyGenTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					mldsa = GetAlgorithm(test_vectors.TestGroups[i].ParameterSet, test_group.Deterministic);

					mldsa.ml_keygen(out pk, out sk, seed: test_case.SeedBytes);
					CollectionAssert.AreEqual(test_case.PublicKeyBytes, pk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Public key mismatch");
					CollectionAssert.AreEqual(test_case.SecretKeyBytes, sk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Secret key mismatch");
				}
			}
		}

		[TestMethod]
		public void TestAvcpSigGen() {
			AcvpMlDsaTestVectors<AcvpMlDsaSigGenTestCase> test_vectors;
			MlDsaBase mldsa;
			byte[] sig;
			byte[] null_rnd;

			null_rnd = new byte[32];

			test_vectors = AcvpMlDsa.LoadSigGenVectors("ML_DSA.sigGen.prompt.json", "ML_DSA.sigGen.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpMlDsaTestGroup<AcvpMlDsaSigGenTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpMlDsaSigGenTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					mldsa = GetAlgorithm(test_vectors.TestGroups[i].ParameterSet, test_group.Deterministic);

					mldsa.ml_sign_internal(out sig, test_case.MessageBytes, Array.Empty<byte>(), test_group.Deterministic ? null_rnd : test_case.RandomBytes, test_case.SecretKeyBytes);
					CollectionAssert.AreEqual(test_case.SignatureBytes, sig, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Signature mismatch");
				}
			}
		}

		[TestMethod]
		public void TestAvcpSigVer() {
			AcvpMlDsaTestVectors<AcvpMlDsaSigVerTestCase> test_vectors;
			MlDsaBase mldsa;
			byte[] null_rnd;
			int ret;

			null_rnd = new byte[32];


			test_vectors = AcvpMlDsa.LoadSigVerVectors("ML_DSA.sigVer.prompt.json", "ML_DSA.sigVer.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpMlDsaTestGroup<AcvpMlDsaSigVerTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpMlDsaSigVerTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					mldsa = GetAlgorithm(test_vectors.TestGroups[i].ParameterSet, false);

					ret = mldsa.ml_verify_internal(test_case.SignatureBytes, test_case.MessageBytes, Array.Empty<byte>(), test_group.PublicKeyBytes);
					Assert.AreEqual(test_case.TestPassed, ret == 0, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Signature verification mismatch");
				}
			}
		}

		private MlDsaBase GetAlgorithm(string parameter_set, bool deterministic) {
			switch (parameter_set) {
				case "ML-DSA-44":
					return new MlDsa44(deterministic);
				case "ML-DSA-65":
					return new MlDsa65(deterministic);
				case "ML-DSA-87":
					return new MlDsa87(deterministic);

				default:
					throw new NotImplementedException($"ParameterSet {parameter_set} not supported");
			}
		}
	}
}