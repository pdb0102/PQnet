using System.Text;

using mldsa_net.test.AVCP;

namespace mldsa_net.test;

[TestClass]
public sealed class MlDsa {
	[TestMethod]
	public void TestAvcpKeyGen() {
		AcvpMlDsaTestVectors<AcvpMlDsaKeyGenTestCase> test_vectors;
		DilithiumBase dilithium;
		Dilithium2 dilithium2;
		Dilithium3 dilithium3;
		Dilithium5 dilithium5;
		byte[] pk;
		byte[] sk;

		dilithium2 = new Dilithium2();
		dilithium3 = new Dilithium3();
		dilithium5 = new Dilithium5();

		test_vectors = AcvpMldsa.LoadKeyGenVectors("keyGen.prompt.json", "keyGen.expectedResults.json");

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
		DilithiumBase dilithium;
		Dilithium2 dilithium2;
		Dilithium3 dilithium3;
		Dilithium5 dilithium5;
		byte[] sig;
		byte[] null_rnd;

		dilithium2 = new Dilithium2();
		dilithium3 = new Dilithium3();
		dilithium5 = new Dilithium5();

		null_rnd = new byte[32];

		test_vectors = AcvpMldsa.LoadSigGenVectors("sigGen.prompt.json", "sigGen.expectedResults.json");

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
		DilithiumBase dilithium;
		Dilithium2 dilithium2;
		Dilithium3 dilithium3;
		Dilithium5 dilithium5;
		byte[] sig;
		byte[] null_rnd;
		int ret;

		dilithium2 = new Dilithium2();
		dilithium3 = new Dilithium3();
		dilithium5 = new Dilithium5();

		null_rnd = new byte[32];


		test_vectors = AcvpMldsa.LoadSigVerVectors("sigVer.prompt.json", "sigVer.expectedResults.json");

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
