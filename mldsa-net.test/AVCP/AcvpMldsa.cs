using System.Reflection;
using System.Runtime.Serialization.Json;

namespace mldsa_net.test.AVCP;
internal class AcvpMldsa {
	public static AcvpMlDsaTestVectors<AcvpMlDsaKeyGenTestCase> LoadkeyGenVectors(string prompt_resouce, string expected_resource) {
		AcvpMlDsaTestVectors<AcvpMlDsaKeyGenTestCase> prompt;
		AcvpMlDsaTestVectors<AcvpMlDsaKeyGenTestCase> expected;

		prompt = DeserializeVectors<AcvpMlDsaKeyGenTestCase>(LoadFile(prompt_resouce));
		expected = DeserializeVectors<AcvpMlDsaKeyGenTestCase>(LoadFile(expected_resource));

		// Fiddle them together
		for (int i = 0; i < prompt.TestGroups.Count; i++) {
			for (int j = 0; j < expected.TestGroups.Count; j++) {
				if (prompt.TestGroups[i].TgId != expected.TestGroups[j].TgId) {
					continue;
				}
				MergeTests(prompt.TestGroups[i], expected.TestGroups[j]);
			}
		}
		return prompt;
	}

	private static void MergeTests(AcvpMlDsaTestGroup<AcvpMlDsaKeyGenTestCase> prompt, AcvpMlDsaTestGroup<AcvpMlDsaKeyGenTestCase> expected) {
		if (prompt.Tests.Count != expected.Tests.Count) {
			Assert.Fail($"Mismatched test count: {prompt.Tests.Count} != {expected.Tests.Count}");
		}
		for (int i = 0; i < prompt.Tests.Count; i++) {
			for (int j = 0; j < expected.Tests.Count; j++) {
				if (prompt.Tests[i].TcId != expected.Tests[j].TcId) {
					continue;
				}
				prompt.Tests[i].SecretKey = expected.Tests[j].SecretKey;
				prompt.Tests[i].PublicKey = expected.Tests[j].PublicKey;
			}
		}
	}

	public static AcvpMlDsaTestVectors<T> DeserializeVectors<T>(byte[] serialized) {
		DataContractJsonSerializer serializer;

		try {
			serializer = new DataContractJsonSerializer(typeof(AcvpMlDsaTestVectors<T>));
			using (MemoryStream ms = new MemoryStream(serialized)) {
				return (AcvpMlDsaTestVectors<T>)serializer.ReadObject(ms);
			}
		} catch {
			return null;
		}
	}

	public static byte[] LoadFile(string fileName) {
		Assembly assembly;
		List<string> resources;

		assembly = Assembly.GetExecutingAssembly();
		resources = new List<string>(assembly.GetManifestResourceNames());
		for (int i = 0; i < resources.Count; i++) {
			if (resources[i].EndsWith(fileName)) {
				using (Stream stream = assembly.GetManifestResourceStream(resources[i])) {
					using (MemoryStream ms = new MemoryStream()) {
						stream.CopyTo(ms);
						return ms.ToArray();
					}
				}
			}
		}
		Assert.Fail($"Failed to find embedded file: {fileName}");
		return null;
	}

}
