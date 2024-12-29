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

using System.Reflection;
using System.Runtime.Serialization.Json;

namespace PQnet.test.AVCP {
	internal class AcvpMlDsa {
		public static AcvpMlDsaTestVectors<AcvpMlDsaKeyGenTestCase> LoadKeyGenVectors(string prompt_resouce, string expected_resource) {
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

		public static AcvpMlDsaTestVectors<AcvpMlDsaSigGenTestCase> LoadSigGenVectors(string prompt_resouce, string expected_resource) {
			AcvpMlDsaTestVectors<AcvpMlDsaSigGenTestCase> prompt;
			AcvpMlDsaTestVectors<AcvpMlDsaSigGenTestCase> expected;

			prompt = DeserializeVectors<AcvpMlDsaSigGenTestCase>(LoadFile(prompt_resouce));
			expected = DeserializeVectors<AcvpMlDsaSigGenTestCase>(LoadFile(expected_resource));

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

		public static AcvpMlDsaTestVectors<AcvpMlDsaSigVerTestCase> LoadSigVerVectors(string prompt_resouce, string expected_resource) {
			AcvpMlDsaTestVectors<AcvpMlDsaSigVerTestCase> prompt;
			AcvpMlDsaTestVectors<AcvpMlDsaSigVerTestCase> expected;

			prompt = DeserializeVectors<AcvpMlDsaSigVerTestCase>(LoadFile(prompt_resouce));
			expected = DeserializeVectors<AcvpMlDsaSigVerTestCase>(LoadFile(expected_resource));

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

		private static void MergeTests(AcvpMlDsaTestGroup<AcvpMlDsaSigGenTestCase> prompt, AcvpMlDsaTestGroup<AcvpMlDsaSigGenTestCase> expected) {
			if (prompt.Tests.Count != expected.Tests.Count) {
				Assert.Fail($"Mismatched test count: {prompt.Tests.Count} != {expected.Tests.Count}");
			}
			for (int i = 0; i < prompt.Tests.Count; i++) {
				for (int j = 0; j < expected.Tests.Count; j++) {
					if (prompt.Tests[i].TcId != expected.Tests[j].TcId) {
						continue;
					}
					prompt.Tests[i].Signature = expected.Tests[j].Signature;
				}
			}
		}

		private static void MergeTests(AcvpMlDsaTestGroup<AcvpMlDsaSigVerTestCase> prompt, AcvpMlDsaTestGroup<AcvpMlDsaSigVerTestCase> expected) {
			if (prompt.Tests.Count != expected.Tests.Count) {
				Assert.Fail($"Mismatched test count: {prompt.Tests.Count} != {expected.Tests.Count}");
			}
			for (int i = 0; i < prompt.Tests.Count; i++) {
				for (int j = 0; j < expected.Tests.Count; j++) {
					if (prompt.Tests[i].TcId != expected.Tests[j].TcId) {
						continue;
					}
					prompt.Tests[i].TestPassed = expected.Tests[j].TestPassed;
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
}