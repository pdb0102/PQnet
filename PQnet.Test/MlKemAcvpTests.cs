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

using PQnet.test.AVCP;

namespace PQnet.test {

	[TestClass]
	public sealed class MlKemAcvpTests {
		[TestMethod]
		public void TestAvcpKeyGen() {
			AcvpMlKemTestVectors<AcvpMlKemKeyGenTestCase> test_vectors;
			MlKemBase mlkem;
			byte[] ek;
			byte[] dk;

			test_vectors = AcvpMlKem.LoadKeyGenVectors("ML_KEM.keyGen.prompt.json", "ML_KEM.keyGen.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpMlKemTestGroup<AcvpMlKemKeyGenTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					byte[] coins;
					AcvpMlKemKeyGenTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					mlkem = GetAlgorithm(test_vectors.TestGroups[i].ParameterSet);

					coins = new byte[test_case.DBytes.Length + test_case.ZBytes.Length];
					Array.Copy(test_case.DBytes, 0, coins, 0, test_case.DBytes.Length);
					Array.Copy(test_case.ZBytes, 0, coins, test_case.DBytes.Length, test_case.ZBytes.Length);

					//mlkem.GenerateKeyPair(out ek, out dk, test_case.DBytes, test_case.ZBytes, out _);
					mlkem.crypto_kem_keypair_derand(out ek, out dk, coins);

					CollectionAssert.AreEqual(test_case.EncapsulationKeyBytes, ek, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Encapsulation key mismatch");
					CollectionAssert.AreEqual(test_case.DecapsulationKeyBytes, dk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Decapsulation key mismatch");

					Debug.WriteLine($"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet}: Passed");
				}
			}
		}

		[TestMethod]
		public void TestAvcpEncapDecap() {
			AcvpMlKemTestVectors<AcvpMlKemEncapDecapTestCase> test_vectors;
			MlKemBase mlkem;
			byte[] ct;
			byte[] ss;

			test_vectors = AcvpMlKem.LoadEncapDecapVectors("ML_KEM.encapDecap.prompt.json", "ML_KEM.encapDecap.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpMlKemTestGroup<AcvpMlKemEncapDecapTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpMlKemEncapDecapTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					mlkem = GetAlgorithm(test_vectors.TestGroups[i].ParameterSet);

					switch (test_group.Function.ToLower()) {
						case "encapsulation":
							mlkem.crypto_kem_enc_derand(out ct, out ss, test_case.EncapsulationKeyBytes, test_case.RandomnessBytes);
							CollectionAssert.AreEqual(test_case.CiphertextBytes, ct, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet} {test_group.Function}: Ciphertext mismatch");
							CollectionAssert.AreEqual(test_case.SecretKeyBytes, ss, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet} {test_group.Function}: Secret Key mismatch");
							break;
						case "decapsulation":
							mlkem.crypto_kem_dec(out ss, test_case.CiphertextBytes, test_group.DecapsulationKeyBytes);
							CollectionAssert.AreEqual(test_case.SecretKeyBytes, ss, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet} {test_group.Function}: Secret Key mismatch");
							break;
					}
					Debug.WriteLine($"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_vectors.TestGroups[i].ParameterSet} {test_group.Function}: Passed");
				}
			}
		}

		private MlKemBase GetAlgorithm(string parameter_set) {
			switch (parameter_set) {
				case "ML-KEM-512":
					return new MlKem512();
				case "ML-KEM-768":
					return new MlKem768();
				case "ML-KEM-1024":
					return new MlKem1024();

				default:
					throw new NotImplementedException($"ParameterSet {parameter_set} not supported");
			}
		}
	}
}