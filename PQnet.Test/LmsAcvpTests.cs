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
	public sealed class LmsAcvpTests {
		[TestMethod]
		public void TestAvcpKeyGen() {
			AcvpLmsTestVectors<AcvpLmsKeyGenTestCase> test_vectors;
			ILmsHashAlgorithm hash;
			byte[] pk;
			byte[] sk;
			uint lms_typecode;
			uint ots_typecode;

			test_vectors = AcvpLms.LoadKeyGenVectors("LMS.keyGen.prompt.json", "LMS.keyGen.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpLmsTestGroup<AcvpLmsKeyGenTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpLmsKeyGenTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					hash = GetHashAlgorithm(test_group.LmsMode);
					lms_typecode = GetLmsTypeCode(test_group.LmsMode);
					ots_typecode = GetOtsTypeCode(test_group.LmOtsMode);

					Lms.GenerateKeyPair(hash, lms_typecode, ots_typecode, test_case.IBytes, test_case.SeedBytes, out pk, out sk);

					CollectionAssert.AreEqual(test_case.PublicKeyBytes, pk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_group.LmsMode}/{test_group.LmOtsMode}: Public key mismatch");
					CollectionAssert.AreEqual(test_case.PrivateKeyBytes, sk, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_group.LmsMode}/{test_group.LmOtsMode}: Private key mismatch");
					Debug.WriteLine($"Passed - TestGroup {test_group.TgId}, TestCase {test_case.TcId}: LMS Mode: {test_group.LmsMode}, OTS Mode: {test_group.LmOtsMode}");
				}
			}
		}

		[TestMethod]
		public void TestAvcpSigGen() {
			AcvpLmsTestVectors<AcvpLmsSigGenTestCase> test_vectors;
			ILmsHashAlgorithm hash;
			byte[] sig;
			byte[] updated_sk;

			test_vectors = AcvpLms.LoadSigGenVectors("LMS.sigGen.prompt.json", "LMS.sigGen.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpLmsTestGroup<AcvpLmsSigGenTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpLmsSigGenTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					hash = GetHashAlgorithm(test_group.LmsMode);

					sig = Lms.Sign(hash, test_case.PrivateKeyBytes, test_case.MessageBytes, out updated_sk);

					CollectionAssert.AreEqual(test_case.SignatureBytes, sig, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_group.LmsMode}/{test_group.LmOtsMode}: Signature mismatch");
					Debug.WriteLine($"Passed - TestGroup {test_group.TgId}, TestCase {test_case.TcId}: LMS Mode: {test_group.LmsMode}, OTS Mode: {test_group.LmOtsMode}");
				}
			}
		}

		[TestMethod]
		public void TestAvcpSigVer() {
			AcvpLmsTestVectors<AcvpLmsSigVerTestCase> test_vectors;
			ILmsHashAlgorithm hash;
			bool result;

			test_vectors = AcvpLms.LoadSigVerVectors("LMS.sigVer.prompt.json", "LMS.sigVer.expectedResults.json");

			for (int i = 0; i < test_vectors.TestGroups.Count; i++) {
				AcvpLmsTestGroup<AcvpLmsSigVerTestCase> test_group;

				test_group = test_vectors.TestGroups[i];

				for (int j = 0; j < test_vectors.TestGroups[i].Tests.Count; j++) {
					AcvpLmsSigVerTestCase test_case;

					test_case = test_vectors.TestGroups[i].Tests[j];

					hash = GetHashAlgorithm(test_group.LmsMode);

					result = Lms.Verify(hash, test_group.PublicKeyBytes, test_case.SignatureBytes, test_case.MessageBytes);

					Assert.AreEqual(test_case.TestPassed, result, $"TestGroup {test_group.TgId}, TestCase {test_case.TcId}, {test_group.LmsMode}/{test_group.LmOtsMode}: Signature verification mismatch");
					Debug.WriteLine($"Passed - TestGroup {test_group.TgId}, TestCase {test_case.TcId}: LMS Mode: {test_group.LmsMode}, OTS Mode: {test_group.LmOtsMode}");
				}
			}
		}

		private static ILmsHashAlgorithm GetHashAlgorithm(string lms_mode) {
			if (lms_mode.Contains("SHA256")) {
				return new Sha256LmsHash();
			}
			throw new NotImplementedException($"Hash algorithm for {lms_mode} not implemented");
		}

		private static uint GetLmsTypeCode(string lms_mode) {
			switch (lms_mode) {
				case "LMS_SHA256_M32_H5":
					return Lms.LMS_SHA256_M32_H5;
				case "LMS_SHA256_M32_H10":
					return Lms.LMS_SHA256_M32_H10;
				case "LMS_SHA256_M32_H15":
					return Lms.LMS_SHA256_M32_H15;
				case "LMS_SHA256_M32_H20":
					return Lms.LMS_SHA256_M32_H20;
				case "LMS_SHA256_M32_H25":
					return Lms.LMS_SHA256_M32_H25;
				case "LMS_SHA256_M24_H5":
				case "LMS_SHA256_M24_H10":
				case "LMS_SHA256_M24_H15":
				case "LMS_SHA256_M24_H20":
				case "LMS_SHA256_M24_H25":
					throw new NotImplementedException($"LMS mode {lms_mode} (M24) not implemented - only M32 supported");
				default:
					throw new ArgumentException($"Unknown LMS mode: {lms_mode}");
			}
		}

		private static uint GetOtsTypeCode(string ots_mode) {
			switch (ots_mode) {
				case "LMOTS_SHA256_N32_W1":
					return LmOts.LMOTS_SHA256_N32_W1;
				case "LMOTS_SHA256_N32_W2":
					return LmOts.LMOTS_SHA256_N32_W2;
				case "LMOTS_SHA256_N32_W4":
					return LmOts.LMOTS_SHA256_N32_W4;
				case "LMOTS_SHA256_N32_W8":
					return LmOts.LMOTS_SHA256_N32_W8;
				case "LMOTS_SHA256_N24_W1":
				case "LMOTS_SHA256_N24_W2":
				case "LMOTS_SHA256_N24_W4":
				case "LMOTS_SHA256_N24_W8":
					throw new NotImplementedException($"OTS mode {ots_mode} (N24) not implemented - only N32 supported");
				default:
					throw new ArgumentException($"Unknown OTS mode: {ots_mode}");
			}
		}
	}
}
