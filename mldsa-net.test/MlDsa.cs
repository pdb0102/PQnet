using mldsa_net.test.AVCP;

namespace mldsa_net.test;

[TestClass]
public sealed class MlDsa {
	[TestMethod]
	public void TestAvcpKeyGen() {
		AcvpMlDsaTestVectors<AcvpMlDsaKeyGenTestCase> test_vectors;
		byte[] pk;
		byte[] sk;


		test_vectors = AcvpMldsa.LoadkeyGenVectors("keyGen.prompt.json", "keyGen.expectedResults.json");

		for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
			for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
				AcvpMlDsaKeyGenTestCase test_case;

				test_case = test_vectors.TestGroups[i].Tests[j];

				// Perform the test
				switch (test_vectors.TestGroups[i].ParameterSet) {
					case "ML-DSA-44":
						Dilithium2 dilithium2;

						dilithium2 = new Dilithium2();
						dilithium2.crypto_sign_keypair(out pk, out sk, seed: test_case.SeedBytes);
						break;
					case "ML-DSA-65":
						Dilithium3 dilithium3;

						dilithium3 = new Dilithium3();
						dilithium3.crypto_sign_keypair(out pk, out sk, seed: test_case.SeedBytes);
						break;
					case "ML-DSA-87":
						Dilithium5 dilithium5;

						dilithium5 = new Dilithium5();
						dilithium5.crypto_sign_keypair(out pk, out sk, seed: test_case.SeedBytes);
						break;
					default:
						throw new NotImplementedException($"ParameterSet {test_vectors.TestGroups[i].ParameterSet} not supported");
				}

				CollectionAssert.AreEqual(test_case.PublicKeyBytes, pk, $"TestGroup {test_vectors.TestGroups[i].TgId}, TestCase {test_case.TcId}: Public key mismatch");
				CollectionAssert.AreEqual(test_case.SecretKeyBytes, sk, $"TestGroup {test_vectors.TestGroups[i].TgId}, TestCase {test_case.TcId}: Secret key mismatch");
			}
		}
	}
}
