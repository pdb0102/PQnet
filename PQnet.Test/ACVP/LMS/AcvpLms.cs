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

using System.Runtime.Serialization.Json;

namespace PQnet.test.AVCP {
	internal class AcvpLms {
		public static AcvpLmsTestVectors<AcvpLmsKeyGenTestCase> LoadKeyGenVectors(string prompt_resource, string expected_resource) {
			AcvpLmsTestVectors<AcvpLmsKeyGenTestCase> prompt;
			AcvpLmsTestVectors<AcvpLmsKeyGenTestCase> expected;

			prompt = DeserializeVectors<AcvpLmsKeyGenTestCase>(Utilities.LoadFile(prompt_resource));
			expected = DeserializeVectors<AcvpLmsKeyGenTestCase>(Utilities.LoadFile(expected_resource));

			// Merge them together
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

		public static AcvpLmsTestVectors<AcvpLmsSigGenTestCase> LoadSigGenVectors(string prompt_resource, string expected_resource) {
			AcvpLmsTestVectors<AcvpLmsSigGenTestCase> prompt;
			AcvpLmsTestVectors<AcvpLmsSigGenTestCase> expected;

			prompt = DeserializeVectors<AcvpLmsSigGenTestCase>(Utilities.LoadFile(prompt_resource));
			expected = DeserializeVectors<AcvpLmsSigGenTestCase>(Utilities.LoadFile(expected_resource));

			// Merge them together
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

		public static AcvpLmsTestVectors<AcvpLmsSigVerTestCase> LoadSigVerVectors(string prompt_resource, string expected_resource) {
			AcvpLmsTestVectors<AcvpLmsSigVerTestCase> prompt;
			AcvpLmsTestVectors<AcvpLmsSigVerTestCase> expected;

			prompt = DeserializeVectors<AcvpLmsSigVerTestCase>(Utilities.LoadFile(prompt_resource));
			expected = DeserializeVectors<AcvpLmsSigVerTestCase>(Utilities.LoadFile(expected_resource));

			// Merge them together
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

		private static void MergeTests(AcvpLmsTestGroup<AcvpLmsKeyGenTestCase> prompt, AcvpLmsTestGroup<AcvpLmsKeyGenTestCase> expected) {
			if (prompt.Tests.Count != expected.Tests.Count) {
				Assert.Fail($"Mismatched test count: {prompt.Tests.Count} != {expected.Tests.Count}");
			}
			for (int i = 0; i < prompt.Tests.Count; i++) {
				for (int j = 0; j < expected.Tests.Count; j++) {
					if (prompt.Tests[i].TcId != expected.Tests[j].TcId) {
						continue;
					}
					prompt.Tests[i].PrivateKey = expected.Tests[j].PrivateKey;
					prompt.Tests[i].PublicKey = expected.Tests[j].PublicKey;
				}
			}
		}

		private static void MergeTests(AcvpLmsTestGroup<AcvpLmsSigGenTestCase> prompt, AcvpLmsTestGroup<AcvpLmsSigGenTestCase> expected) {
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

		private static void MergeTests(AcvpLmsTestGroup<AcvpLmsSigVerTestCase> prompt, AcvpLmsTestGroup<AcvpLmsSigVerTestCase> expected) {
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

		public static AcvpLmsTestVectors<T> DeserializeVectors<T>(byte[] serialized) {
			DataContractJsonSerializer serializer;

			try {
				serializer = new DataContractJsonSerializer(typeof(AcvpLmsTestVectors<T>));
				using (MemoryStream ms = new MemoryStream(serialized)) {
					return (AcvpLmsTestVectors<T>)serializer.ReadObject(ms);
				}
			} catch {
				return null;
			}
		}
	}
}
