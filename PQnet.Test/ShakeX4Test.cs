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
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;
using System.Text;

using PQnet.Digest;

namespace PQnet.test {
	/// <summary>
	/// Tests for the various ShakeX4 internal methods
	/// </summary>
	[TestClass]
	public sealed class ShakeX4Test {
		private ulong[] pre_rounds = {
			0x968B4186D2D28B32, 0x7CE2A174B06C20F8, 0x5804FFE4EB2F4112, 0x63C00DE15107304A, 0xF3B8F913531FB963,
			0xA3852B4DDE235FAB, 0xA9C02232B8B6B46A, 0xDC2F675B6065CDD0, 0xAC0027C4EDE2F22E, 0x24B7678FA1851DE1,
			0x3DB58B5B0FBC6F2D, 0x4EAC8796D177589F, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0x5B0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private ulong[] post_rounds = {
			0xC32860C73B5E2F85, 0xD5E8ABDB87CF84E8, 0x51ED04C4687C5230, 0xAAB35C0EC4644553, 0x74D1930DB718308F,
			0x04D0415C92C59D3F, 0xE7F8FC52074F7298, 0xA78A23843ABFBA6B, 0xC815B5D15565F517, 0xF0E7A281721DB720,
			0x4C5CE32D5096FEE1, 0xE1B1677BF12755F9, 0xFE47A981716B620B, 0x2B956985A148ACA3, 0x845CCE92780F5F46,
			0xF419AB00167396F1, 0x176C28EDF80582E5, 0x4D80DE191FDD3345, 0x7B949CD70697E11D, 0x28DE4463476909C7,
			0x0E33500A05562FFB, 0x12E7D18F49B68EEB, 0x95A55BB2D8494705, 0x8B499AF88DB92D4A, 0xC61B4840A5C240D1,
		};

		[TestMethod]
		public void Test24RoundPermutation() {
			KeccakBaseX4 shake;

			if (!Avx2.IsSupported) {
				Assert.Inconclusive("AVX2 not supported");
			}

			shake = new KeccakBaseX4();
			for (int i = 0; i < 25; i++) {
				shake.state[i] = Vector256.Create(pre_rounds[i], pre_rounds[i], pre_rounds[i], pre_rounds[i]);
			}
			shake.PermuteAll_24rounds();

			for (int i = 0; i < 25; i++) {
				Assert.AreEqual(post_rounds[i], shake.state[i][0], $"First state A[{i}] did not match");
				Assert.AreEqual(post_rounds[i], shake.state[i][1], $"Second state A[{i}] did not match");
				Assert.AreEqual(post_rounds[i], shake.state[i][2], $"Third state A[{i}] did not match");
				Assert.AreEqual(post_rounds[i], shake.state[i][3], $"Fourth state A[{i}] did not match");
			}
		}

		private ulong[] pre_add_bytes_state = {
			0x782A084A131E2B49, 0xB4BFCF47B4516511, 0xD0620B137917A103, 0x72377BF91ED7DFA6, 0xF3629BFEC6AAAB74,
			0x06449ECBE9BDD0CC, 0xBF64ED3FC95EEF63, 0xB315735BFE359B82, 0xF31ED54F5318803F, 0x31FC2C2B60FC612F,
			0x5B2556E3F0CACF08, 0x4EAC8796D1775880, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private ulong[] post_add_bytes_state_full_block = {
			0x968B4186D2D28B32, 0x7CE2A174B06C20F8, 0x5804FFE4EB2F4112, 0x63C00DE15107304A, 0xF3B8F913531FB963,
			0xA3852B4DDE235FAB, 0xA9C02232B8B6B46A, 0xDC2F675B6065CDD0, 0xAC0027C4EDE2F22E, 0x24B7678FA1851DE1,
			0x3DB58B5B0FBC6F2D, 0x4EAC8796D1775880, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private ulong[] post_add_bytes_state_one_less = {
			0x968B4186D2D28B32, 0x7CE2A174B06C20F8, 0x5804FFE4EB2F4112, 0x63C00DE15107304A, 0xF3B8F913531FB963,
			0xA3852B4DDE235FAB, 0xA9C02232B8B6B46A, 0xDC2F675B6065CDD0, 0xAC0027C4EDE2F22E, 0x24B7678FA1851DE1,
			0x5BB58B5B0FBC6F2D, 0x4EAC8796D1775880, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private byte[] bytes_input = {
			0x7b, 0xa0, 0xcc, 0xc1, 0xcc, 0x49, 0xa1, 0xee,
			0xe9, 0x45, 0x3d, 0x4, 0x33, 0x6e, 0x5d, 0xc8, 0x11, 0xe0,
			0x38, 0x92, 0xf7, 0xf4, 0x66, 0x88, 0xec, 0xef, 0xd0, 0x4f,
			0x18, 0x76, 0xf7, 0x11, 0x17, 0x12, 0xb5, 0x95, 0xed, 0x62,
			0xda, 0x0, 0x67, 0x8f, 0x9e, 0x37, 0x86, 0xb5, 0xc1, 0xa5,
			0x9, 0x5b, 0xe8, 0x71, 0xd, 0xcf, 0xa4, 0x16, 0x52, 0x56,
			0x50, 0x9e, 0x0, 0x14, 0x3a, 0x6f, 0x11, 0x72, 0xfa, 0xbe,
			0x8b, 0xf2, 0x1e, 0x5f, 0xce, 0x7c, 0x79, 0xc1, 0xa4, 0x4b,
			0x4b, 0x15, 0x25, 0xa0, 0x76, 0xff, 0xb8, 0xdd, 0x90, 0x66
		};
		[TestMethod]
		public void TestAddBytesFullBlock() {
			KeccakBaseX4 shake;

			if (!Avx2.IsSupported) {
				Assert.Inconclusive("AVX2 not supported");
			}

			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(pre_add_bytes_state[s], pre_add_bytes_state[s], pre_add_bytes_state[s], pre_add_bytes_state[s]);
				}
				Stopwatch timer;

				timer = Stopwatch.StartNew();
				shake.AddBytes(i, 0, bytes_input, bytes_input.Length);
				timer.Stop();
				Console.WriteLine($"AddBytes {i} took {timer.ElapsedTicks} ticks");
				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? post_add_bytes_state_full_block[s] : pre_add_bytes_state[s], shake.state[s][0], $"First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? post_add_bytes_state_full_block[s] : pre_add_bytes_state[s], shake.state[s][1], $"Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? post_add_bytes_state_full_block[s] : pre_add_bytes_state[s], shake.state[s][2], $"Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? post_add_bytes_state_full_block[s] : pre_add_bytes_state[s], shake.state[s][3], $"Fourth state A[{i}] did not match");
				}
			}
		}

		[TestMethod]
		public void TestAddBytesOneByteShortOfFullBlock() {
			KeccakBaseX4 shake;

			if (!Avx2.IsSupported) {
				Assert.Inconclusive("AVX2 not supported");
			}

			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(pre_add_bytes_state[s], pre_add_bytes_state[s], pre_add_bytes_state[s], pre_add_bytes_state[s]);
				}

				shake.AddBytes(i, 0, bytes_input, bytes_input.Length - 1);

				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? post_add_bytes_state_one_less[s] : pre_add_bytes_state[s], shake.state[s][0], $"First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? post_add_bytes_state_one_less[s] : pre_add_bytes_state[s], shake.state[s][1], $"Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? post_add_bytes_state_one_less[s] : pre_add_bytes_state[s], shake.state[s][2], $"Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? post_add_bytes_state_one_less[s] : pre_add_bytes_state[s], shake.state[s][3], $"Fourth state A[{i}] did not match");
				}
			}
		}

		private ulong[] pre_add_bytes_at_offset_14_state = {
			0x782A084A131E2B49, 0xB4BFCF47B4516511, 0xD0620B137917A103, 0x72377BF91ED7DFA6, 0xF3629BFEC6AAAB74,
			0x06449ECBE9BDD0CC, 0xBF64ED3FC95EEF63, 0xB315735BFE359B82, 0xF31ED54F5318803F, 0x31FC2C2B60FC612F,
			0x5B2556E3F0CACF08, 0x4EAC8796D1775880, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private ulong[] post_add_4_bytes_at_offset_14_state = {
			0x782A084A131E2B49, 0xD1CBCF47B4516511, 0xD0620B137917D570, 0x72377BF91ED7DFA6, 0xF3629BFEC6AAAB74,
			0x06449ECBE9BDD0CC, 0xBF64ED3FC95EEF63, 0xB315735BFE359B82, 0xF31ED54F5318803F, 0x31FC2C2B60FC612F,
			0x5B2556E3F0CACF08, 0x4EAC8796D1775880, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private ulong[] post_add_96_bytes_at_offset_14_state = {
			0x782A084A131E2B49, 0xD1CBCF47B4516511, 0xB5167F601C63D570, 0x17430F8A7BA3ABD5, 0x9616EF8DA3DEDF07,
			0x6330EAB88CC9A4BF, 0xDA10994CAC2A9B10, 0xD66107289B41EFF1, 0x966AA13C366CF44C, 0x548858580588155C,
			0x3E51229095BEBB7B, 0x2BD8F3E5B4032CF3, 0xFC6F6B90BD31D70A, 0xE1A52387E3AC90AD, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private byte[] add_4_bytes_offset_testdata = Encoding.ASCII.GetBytes("test");
		private byte[] add_96_bytes_offset_testdata = Encoding.ASCII.GetBytes("testtesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttesttest");

		[TestMethod]
		public void TestAddBytesWithOffset() {
			KeccakBaseX4 shake;

			if (!Avx2.IsSupported) {
				Assert.Inconclusive("AVX2 not supported");
			}

			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(pre_add_bytes_at_offset_14_state[s], pre_add_bytes_at_offset_14_state[s], pre_add_bytes_at_offset_14_state[s], pre_add_bytes_at_offset_14_state[s]);
				}

				shake.AddBytes(i, 14, add_4_bytes_offset_testdata, add_4_bytes_offset_testdata.Length);

				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? post_add_4_bytes_at_offset_14_state[s] : pre_add_bytes_at_offset_14_state[s], shake.state[s][0], $"Add 4 bytes: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? post_add_4_bytes_at_offset_14_state[s] : pre_add_bytes_at_offset_14_state[s], shake.state[s][1], $"Add 4 bytes: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? post_add_4_bytes_at_offset_14_state[s] : pre_add_bytes_at_offset_14_state[s], shake.state[s][2], $"Add 4 bytes: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? post_add_4_bytes_at_offset_14_state[s] : pre_add_bytes_at_offset_14_state[s], shake.state[s][3], $"Add 4 bytes: Fourth state A[{i}] did not match");
				}
			}

			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(pre_add_bytes_at_offset_14_state[s], pre_add_bytes_at_offset_14_state[s], pre_add_bytes_at_offset_14_state[s], pre_add_bytes_at_offset_14_state[s]);
				}

				shake.AddBytes(i, 14, add_96_bytes_offset_testdata, add_96_bytes_offset_testdata.Length);

				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? post_add_96_bytes_at_offset_14_state[s] : pre_add_bytes_at_offset_14_state[s], shake.state[s][0], $"Add 96 bytes: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? post_add_96_bytes_at_offset_14_state[s] : pre_add_bytes_at_offset_14_state[s], shake.state[s][1], $"Add 96 bytes: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? post_add_96_bytes_at_offset_14_state[s] : pre_add_bytes_at_offset_14_state[s], shake.state[s][2], $"Add 96 bytes: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? post_add_96_bytes_at_offset_14_state[s] : pre_add_bytes_at_offset_14_state[s], shake.state[s][3], $"Add 96 bytes: Fourth state A[{i}] did not match");
				}
			}
		}

		private ulong[] pre_add_single_byte_state = {
			0x782A084A131E2B49, 0xB4BFCF47B4516511, 0xD0620B137917A103, 0x72377BF91ED7DFA6, 0xF3629BFEC6AAAB74,
			0x06449ECBE9BDD0CC, 0xBF64ED3FC95EEF63, 0xB315735BFE359B82, 0xF31ED54F5318803F, 0x31FC2C2B60FC612F,
			0x5B2556E3F0CACF08, 0x4EAC8796D1775880, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private ulong[] post_add_single_byte_offset88_state = {
			0x782A084A131E2B49, 0xB4BFCF47B4516511, 0xD0620B137917A103, 0x72377BF91ED7DFA6, 0xF3629BFEC6AAAB74,
			0x06449ECBE9BDD0CC, 0xBF64ED3FC95EEF63, 0xB315735BFE359B82, 0xF31ED54F5318803F, 0x31FC2C2B60FC612F,
			0x5B2556E3F0CACF08, 0x4EAC8796D177589F, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private ulong[] post_add_single_byte_offset87_state = {
			0x782A084A131E2B49, 0xB4BFCF47B4516511, 0xD0620B137917A103, 0x72377BF91ED7DFA6, 0xF3629BFEC6AAAB74,
			0x06449ECBE9BDD0CC, 0xBF64ED3FC95EEF63, 0xB315735BFE359B82, 0xF31ED54F5318803F, 0x31FC2C2B60FC612F,
			0x442556E3F0CACF08, 0x4EAC8796D1775880, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		private ulong[] post_add_single_byte_offset83_state = {
			0x782A084A131E2B49, 0xB4BFCF47B4516511, 0xD0620B137917A103, 0x72377BF91ED7DFA6, 0xF3629BFEC6AAAB74,
			0x06449ECBE9BDD0CC, 0xBF64ED3FC95EEF63, 0xB315735BFE359B82, 0xF31ED54F5318803F, 0x31FC2C2B60FC612F,
			0x5B2556E3EFCACF08, 0x4EAC8796D1775880, 0x991B1FE3D845A379, 0xE1A557F486D8E4DE, 0xA2C84FB31145F5F3,
			0x0E391DCA1DA184B9, 0xDB0AB1571F3F8E87, 0x265D6707C86B0285, 0xFB9160853759BD6A, 0x461258AD269A3ECF,
			0x532B64238CB7115E, 0xA184683699119CAA, 0x0D5FF38360B96A8D, 0xDA426FBC72FE3ED5, 0x58146CF3B252723B,
		};

		[TestMethod]
		public void TestAddByte() {
			KeccakBaseX4 shake;

			if (!Avx2.IsSupported) {
				Assert.Inconclusive("AVX2 not supported");
			}

			// Offset 88
			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(pre_add_single_byte_state[s], pre_add_single_byte_state[s], pre_add_single_byte_state[s], pre_add_single_byte_state[s]);
				}

				shake.AddByte(i, 88, 0x1f);

				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? post_add_single_byte_offset88_state[s] : pre_add_bytes_state[s], shake.state[s][0], $"Offset 88: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? post_add_single_byte_offset88_state[s] : pre_add_bytes_state[s], shake.state[s][1], $"Offset 88: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? post_add_single_byte_offset88_state[s] : pre_add_bytes_state[s], shake.state[s][2], $"Offset 88: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? post_add_single_byte_offset88_state[s] : pre_add_bytes_state[s], shake.state[s][3], $"Offset 88: Fourth state A[{i}] did not match");
				}
			}

			// Offset 87
			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(pre_add_single_byte_state[s], pre_add_single_byte_state[s], pre_add_single_byte_state[s], pre_add_single_byte_state[s]);
				}

				shake.AddByte(i, 87, 0x1f);

				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? post_add_single_byte_offset87_state[s] : pre_add_bytes_state[s], shake.state[s][0], $"Offset 87: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? post_add_single_byte_offset87_state[s] : pre_add_bytes_state[s], shake.state[s][1], $"Offset 87: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? post_add_single_byte_offset87_state[s] : pre_add_bytes_state[s], shake.state[s][2], $"Offset 87: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? post_add_single_byte_offset87_state[s] : pre_add_bytes_state[s], shake.state[s][3], $"Offset 87: Fourth state A[{i}] did not match");
				}
			}

			// Offset 83
			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(pre_add_single_byte_state[s], pre_add_single_byte_state[s], pre_add_single_byte_state[s], pre_add_single_byte_state[s]);
				}

				shake.AddByte(i, 83, 0x1f);

				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? post_add_single_byte_offset83_state[s] : pre_add_bytes_state[s], shake.state[s][0], $"Offset 83: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? post_add_single_byte_offset83_state[s] : pre_add_bytes_state[s], shake.state[s][1], $"Offset 83: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? post_add_single_byte_offset83_state[s] : pre_add_bytes_state[s], shake.state[s][2], $"Offset 83: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? post_add_single_byte_offset83_state[s] : pre_add_bytes_state[s], shake.state[s][3], $"Offset 83: Fourth state A[{i}] did not match");
				}
			}
		}


		private ulong[] pre_extract_bytes = {
			0xC32860C73B5E2F85, 0xD5E8ABDB87CF84E8, 0x51ED04C4687C5230, 0xAAB35C0EC4644553, 0x74D1930DB718308F,
			0x04D0415C92C59D3F, 0xE7F8FC52074F7298, 0xA78A23843ABFBA6B, 0xC815B5D15565F517, 0xF0E7A281721DB720,
			0x4C5CE32D5096FEE1, 0xE1B1677BF12755F9, 0xFE47A981716B620B, 0x2B956985A148ACA3, 0x845CCE92780F5F46,
			0xF419AB00167396F1, 0x176C28EDF80582E5, 0x4D80DE191FDD3345, 0x7B949CD70697E11D, 0x28DE4463476909C7,
			0x0E33500A05562FFB, 0x12E7D18F49B68EEB, 0x95A55BB2D8494705, 0x8B499AF88DB92D4A, 0xC61B4840A5C240D1,
		};

		private byte[] post_extract_expected_offset_0 = {
			0x85, 0x2f, 0x5e, 0x3b, 0xc7, 0x60, 0x28, 0xc3, 0xe8, 0x84, 0xcf, 0x87, 0xdb, 0xab, 0xe8, 0xd5,
			0x30, 0x52, 0x7c, 0x68, 0xc4, 0x04, 0xed, 0x51, 0x53, 0x45, 0x64, 0xc4, 0x0e, 0x5c, 0xb3, 0xaa,
			0x8f, 0x30, 0x18, 0xb7, 0x0d, 0x93, 0xd1, 0x74, 0x3f, 0x9d, 0xc5, 0x92, 0x5c, 0x41, 0xd0, 0x04,
			0x98, 0x72, 0x4f, 0x07, 0x52, 0xfc, 0xf8, 0xe7, 0x6b, 0xba, 0xbf, 0x3a, 0x84, 0x23, 0x8a, 0xa7,
		};

		private byte[] post_extract_expected_offset_1 = {
				  0x2f, 0x5e, 0x3b, 0xc7, 0x60, 0x28, 0xc3, 0xe8, 0x84, 0xcf, 0x87, 0xdb, 0xab, 0xe8, 0xd5,
			0x30, 0x52, 0x7c, 0x68, 0xc4, 0x04, 0xed, 0x51, 0x53, 0x45, 0x64, 0xc4, 0x0e, 0x5c, 0xb3, 0xaa,
			0x8f, 0x30, 0x18, 0xb7, 0x0d, 0x93, 0xd1, 0x74, 0x3f, 0x9d, 0xc5, 0x92, 0x5c, 0x41, 0xd0, 0x04,
			0x98, 0x72, 0x4f, 0x07, 0x52, 0xfc, 0xf8, 0xe7, 0x6b, 0xba, 0xbf, 0x3a, 0x84, 0x23, 0x8a, 0xa7,
			0x17
		};

		private byte[] post_extract_expected_offset_5 = {
										  0x60, 0x28, 0xc3, 0xe8, 0x84, 0xcf, 0x87, 0xdb, 0xab, 0xe8, 0xd5,
			0x30, 0x52, 0x7c, 0x68, 0xc4, 0x04, 0xed, 0x51, 0x53, 0x45, 0x64, 0xc4, 0x0e, 0x5c, 0xb3, 0xaa,
			0x8f, 0x30, 0x18, 0xb7, 0x0d, 0x93, 0xd1, 0x74, 0x3f, 0x9d, 0xc5, 0x92, 0x5c, 0x41, 0xd0, 0x04,
			0x98, 0x72, 0x4f, 0x07, 0x52, 0xfc, 0xf8, 0xe7, 0x6b, 0xba, 0xbf, 0x3a, 0x84, 0x23, 0x8a, 0xa7,
			0x17, 0xf5, 0x65, 0x55, 0xd1
		};

		private byte[] post_extract_expected_offset_5_end_boundary = {
										  0x60, 0x28, 0xc3, 0xe8, 0x84, 0xcf, 0x87, 0xdb, 0xab, 0xe8, 0xd5,
			0x30, 0x52, 0x7c, 0x68, 0xc4, 0x04, 0xed, 0x51, 0x53, 0x45, 0x64, 0xc4, 0x0e, 0x5c, 0xb3, 0xaa,
			0x8f, 0x30, 0x18, 0xb7, 0x0d, 0x93, 0xd1, 0x74, 0x3f, 0x9d, 0xc5, 0x92, 0x5c, 0x41, 0xd0, 0x04,
			0x98, 0x72, 0x4f, 0x07, 0x52, 0xfc, 0xf8, 0xe7, 0x6b, 0xba, 0xbf, 0x3a, 0x84, 0x23, 0x8a, 0xa7,
		};

		private byte[] post_extract_expected_offset_8 = {
															0xe8, 0x84, 0xcf, 0x87, 0xdb, 0xab, 0xe8, 0xd5,
			0x30, 0x52, 0x7c, 0x68, 0xc4, 0x04, 0xed, 0x51, 0x53, 0x45, 0x64, 0xc4, 0x0e, 0x5c, 0xb3, 0xaa,
			0x8f, 0x30, 0x18, 0xb7, 0x0d, 0x93, 0xd1, 0x74, 0x3f, 0x9d, 0xc5, 0x92, 0x5c, 0x41, 0xd0, 0x04,
			0x98, 0x72, 0x4f, 0x07, 0x52, 0xfc, 0xf8, 0xe7, 0x6b, 0xba, 0xbf, 0x3a, 0x84, 0x23, 0x8a, 0xa7,
			0x17, 0xf5, 0x65, 0x55, 0xd1
		};

		[TestMethod]
		public void TestExtractBytes() {
			KeccakBaseX4 shake;
			byte[] output_buffer;

			if (!Avx2.IsSupported) {
				Assert.Inconclusive("AVX2 not supported");
			}

			// Offset 0	- starts and ends on ulong boundary
			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(i == 0 ? pre_extract_bytes[s] : 0, i == 1 ? pre_extract_bytes[s] : 0, i == 2 ? pre_extract_bytes[s] : 0, i == 3 ? pre_extract_bytes[s] : 0);
				}

				// new buffer every time so we don't have left over data from the last round
				output_buffer = new byte[64];
				shake.ExtractBytes(i, 0, output_buffer, 0, 64);

				CollectionAssert.AreEqual(post_extract_expected_offset_0, output_buffer, $"ExtractBytes {i}: Did not match");

				// We don't want the state to change
				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? pre_extract_bytes[s] : 0, shake.state[s][0], $"Offset 88: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? pre_extract_bytes[s] : 0, shake.state[s][1], $"Offset 88: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? pre_extract_bytes[s] : 0, shake.state[s][2], $"Offset 88: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? pre_extract_bytes[s] : 0, shake.state[s][3], $"Offset 88: Fourth state A[{i}] did not match");
				}
			}

			// Offset 1	- 7 bytes from first ulong, 1 byte from last ulong
			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(i == 0 ? pre_extract_bytes[s] : 0, i == 1 ? pre_extract_bytes[s] : 0, i == 2 ? pre_extract_bytes[s] : 0, i == 3 ? pre_extract_bytes[s] : 0);
				}

				// new buffer every time so we don't have left over data from the last round
				output_buffer = new byte[64];
				shake.ExtractBytes(i, 1, output_buffer, 0, 64);

				CollectionAssert.AreEqual(post_extract_expected_offset_1, output_buffer, $"ExtractBytes {i}: Did not match");

				// We don't want the state to change
				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? pre_extract_bytes[s] : 0, shake.state[s][0], $"Offset 88: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? pre_extract_bytes[s] : 0, shake.state[s][1], $"Offset 88: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? pre_extract_bytes[s] : 0, shake.state[s][2], $"Offset 88: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? pre_extract_bytes[s] : 0, shake.state[s][3], $"Offset 88: Fourth state A[{i}] did not match");
				}
			}

			// Offset 5 - 3 bytes from first ulong, 5 bytes from last ulong
			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(i == 0 ? pre_extract_bytes[s] : 0, i == 1 ? pre_extract_bytes[s] : 0, i == 2 ? pre_extract_bytes[s] : 0, i == 3 ? pre_extract_bytes[s] : 0);
				}

				// new buffer every time so we don't have left over data from the last round
				output_buffer = new byte[64];
				shake.ExtractBytes(i, 5, output_buffer, 0, 64);

				CollectionAssert.AreEqual(post_extract_expected_offset_5, output_buffer, $"ExtractBytes {i}: Did not match");

				// We don't want the state to change
				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? pre_extract_bytes[s] : 0, shake.state[s][0], $"Offset 88: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? pre_extract_bytes[s] : 0, shake.state[s][1], $"Offset 88: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? pre_extract_bytes[s] : 0, shake.state[s][2], $"Offset 88: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? pre_extract_bytes[s] : 0, shake.state[s][3], $"Offset 88: Fourth state A[{i}] did not match");
				}
			}

			// Offset 5, length 59 - 3 bytes from first ulong, ends on ulong boundary
			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(i == 0 ? pre_extract_bytes[s] : 0, i == 1 ? pre_extract_bytes[s] : 0, i == 2 ? pre_extract_bytes[s] : 0, i == 3 ? pre_extract_bytes[s] : 0);
				}

				// new buffer every time so we don't have left over data from the last round
				output_buffer = new byte[59];
				shake.ExtractBytes(i, 5, output_buffer, 0, 59);

				CollectionAssert.AreEqual(post_extract_expected_offset_5_end_boundary, output_buffer, $"ExtractBytes {i}: Did not match");

				// We don't want the state to change
				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? pre_extract_bytes[s] : 0, shake.state[s][0], $"Offset 88: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? pre_extract_bytes[s] : 0, shake.state[s][1], $"Offset 88: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? pre_extract_bytes[s] : 0, shake.state[s][2], $"Offset 88: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? pre_extract_bytes[s] : 0, shake.state[s][3], $"Offset 88: Fourth state A[{i}] did not match");
				}
			}

			// Offset 8, length 61 - starts on ulong boundary, ends 3 bytes from end of ulong boundary
			for (int i = 0; i < 4; i++) {
				shake = new KeccakBaseX4();
				for (int s = 0; s < 25; s++) {
					shake.state[s] = Vector256.Create(i == 0 ? pre_extract_bytes[s] : 0, i == 1 ? pre_extract_bytes[s] : 0, i == 2 ? pre_extract_bytes[s] : 0, i == 3 ? pre_extract_bytes[s] : 0);
				}

				// new buffer every time so we don't have left over data from the last round
				output_buffer = new byte[61];
				shake.ExtractBytes(i, 8, output_buffer, 0, 61);

				CollectionAssert.AreEqual(post_extract_expected_offset_8, output_buffer, $"ExtractBytes {i}: Did not match");

				// We don't want the state to change
				for (int s = 0; s < 25; s++) {
					Assert.AreEqual(i == 0 ? pre_extract_bytes[s] : 0, shake.state[s][0], $"Offset 88: First state A[{i}] did not match");
					Assert.AreEqual(i == 1 ? pre_extract_bytes[s] : 0, shake.state[s][1], $"Offset 88: Second state A[{i}] did not match");
					Assert.AreEqual(i == 2 ? pre_extract_bytes[s] : 0, shake.state[s][2], $"Offset 88: Third state A[{i}] did not match");
					Assert.AreEqual(i == 3 ? pre_extract_bytes[s] : 0, shake.state[s][3], $"Offset 88: Fourth state A[{i}] did not match");
				}
			}
		}


		private ulong[] post_block_0 = {
			0xC9834334D2362F28, 0x2B8BA51237858FC4, 0xF9EDB9BD888C78BD, 0x5DC691D14FE45F12, 0x11CA79D90002606B,
			0xE6A4764F80AA5CF6, 0xF8F4D02AD44B4ADF, 0x36EC33AF3B7394F6, 0xA6A7A3C4FB6AC06E, 0xB3B1D19D16784D8F,
			0xDFD0FBA7398BE6A5, 0x3E4D8506074C0B20, 0x3A497BEEDF7F7688, 0x760C6E1A9BCCB2E4, 0x96E1AA9CCED04E74,
			0xBD2CDEED084D065F, 0x6AA4E537E9AFEEA1, 0xA589E42E64344449, 0x788ACFC004CAFA2C, 0x67B7C69E493FD2C0,
			0xD08C0C07A6228E0C, 0x0786C165DAEE1060, 0x7D75A338406C6735, 0x683DEC7172A2D9C8, 0x9513375F3F9B8919,
		};
		private ulong[] post_block_1 = {
			0x38DDF2F853BCD2CF, 0xA408007D124102D0, 0xB069DD7380D16974, 0x9F646190E7D14C15, 0xE0DCB98DE5A7E8F7,
			0xD79C0FDF83DC88C7, 0xA2F0D3F77555B26F, 0x20D07C8DA7F17A46, 0xD9CDF1AB66E280AB, 0x78E9E9B1EFA64034,
			0x1EAB064036190C75, 0xD994F4B0099B5579, 0xA7C3B02BB437E05D, 0x94146DAFA399EF38, 0xFD070D83CFAEA0BB,
			0x885C82B64EE354C6, 0x664DA537CC0CD8CD, 0x58372318C0EBF445, 0xC3EE69958C215981, 0x2F08C838CE67394D,
			0x683C1D0709CF357A, 0xB252EE0F96CB59A1, 0x5A4ECD55619A986B, 0x98F4A5030A84AF02, 0xEEFA9DCF06716C7B,
		};
		private ulong[] post_block_2 = {
			0x20BFE6A072F24153, 0x8B28845430A52807, 0x5FB32CB21B4296C1, 0xE54240BB1224CB29, 0xC9980FFD9D06AC54,
			0xA735B6F97F8FD6EE, 0x0170C43F3F92AADE, 0x968F19F6A106E8AD, 0xEB6DC436CA661FD6, 0x5CF922474B60EDFD,
			0x3410A91FE2250CA0, 0x33F29CCE4E4AD7AC, 0xCA2B7DB473971C2D, 0xC5CC00B31AC71025, 0xEF70AE68B3D23294,
			0x7B76B508B4C37442, 0x516DCB5314FA9515, 0x5E417A964799C1D7, 0xE8737B0BA13D1CFF, 0xDD61D07303F3C7CE,
			0xEE37748125559197, 0xFA4BD4B7CA3FF57F, 0x351369C04E983130, 0xCD518B47DD099E9B, 0xCE68C93A281AF987,
		};
		private ulong[] post_block_3 = {
			0xA0CD584D3A68FFFF, 0xC926516B88B647B7, 0x6343F5FE1EA2D4CC, 0xE0953A18C9BAB885, 0xE5A1296B5BB00C50,
			0x71C4151EF4ABC54C, 0x4AE1FE9222E0DCCA, 0x470054AE6C1E594E, 0x70DC28C879B1F668, 0xDEDC0495BB293D7B,
			0xBDAC52392FDBF2F5, 0x718AE9E5C8C38AB2, 0x0BFBD61871D966F9, 0x889BF50681165201, 0xA46766182A01BAC0,
			0xA6FFD97B43F6325B, 0xAB32712B92A8A6F5, 0x408A381CE8CF75FC, 0x805A5686DA2C048E, 0x2E00BF7A21730092,
			0x547605E12ADFB413, 0x41A406A6533AF951, 0xCBDA56FA3261ECBA, 0x0E4804DF040472C1, 0x74115615FF361052,
		};

		[TestMethod]
		public void TestFastBlockAbsorb() {
			KeccakBaseX4 shake;
			byte[] test_data;
			int offset;
			int ret;

			if (!Avx2.IsSupported) {
				Assert.Inconclusive("AVX2 not supported");
			}

			shake = new KeccakBaseX4(136, 256, 0x1f);

			offset = 0;
			test_data = new byte[136 * 4];
			for (byte i = 0; i < 136; i++) {
				test_data[offset + (i % 8)] = i;
				test_data[offset + 8 + (i % 8)] = (byte)(255 - i);
				test_data[offset + 16 + (i % 8)] = (byte)(200 - i);
				test_data[offset + 24 + (i % 8)] = (byte)(100 + i);
				if (i % 8 == 7) {
					offset += 32;
				}
			};

			ret = shake.Fast_Block_Absorb(test_data, test_data.Length);
			Assert.AreEqual(136 * 4, ret, "KeccakF1600times4_Fast_Block_Absorb did not consume the correct number of bytes");

			for (int s = 0; s < 25; s++) {
				Assert.AreEqual(post_block_0[s], shake.state[s][0], $"First state A[{s}] did not match");
				Assert.AreEqual(post_block_1[s], shake.state[s][1], $"Second state A[{s}] did not match");
				Assert.AreEqual(post_block_2[s], shake.state[s][2], $"Third state A[{s}] did not match");
				Assert.AreEqual(post_block_3[s], shake.state[s][3], $"Fourth state A[{s}] did not match");
			}
		}

		[TestMethod]
		public void TestExtractBytesAll() {
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;
			KeccakBaseX4 shake;
			int s;
			byte[] expected1;
			byte[] expected2;
			byte[] expected3;
			byte[] expected4;
			int expected_idx;

			if (!Avx2.IsSupported) {
				Assert.Inconclusive("AVX2 not supported");
			}

			shake = new KeccakBaseX4(136, 256, 0x1f);

			output1 = new byte[136];
			output2 = new byte[136];
			output3 = new byte[136];
			output4 = new byte[136];

			expected1 = new byte[136];
			expected2 = new byte[136];
			expected3 = new byte[136];
			expected4 = new byte[136];


			s = 0;

			expected_idx = 0;

			for (int i = 0; i < 17; i++) {
				shake.state[i] = Vector256.Create((byte)s, (byte)(s + 1), (byte)(s + 2), (byte)(s + 3), (byte)(s + 4), (byte)(s + 5), (byte)(s + 6), (byte)(s + 7), (byte)(s + 8), (byte)(s + 9), (byte)(s + 10), (byte)(s + 11), (byte)(s + 12), (byte)(s + 13), (byte)(s + 14), (byte)(s + 15), (byte)(s + 16), (byte)(s + 17), (byte)(s + 18), (byte)(s + 19), (byte)(s + 20), (byte)(s + 21), (byte)(s + 22), (byte)(s + 23), (byte)(s + 24), (byte)(s + 25), (byte)(s + 26), (byte)(s + 27), (byte)(s + 28), (byte)(s + 29), (byte)(s + 30), (byte)(s + 31)).AsUInt64();
				for (int x = s; x < s + 8; x++, expected_idx++) {
					expected1[expected_idx] = (byte)x;
					expected2[expected_idx] = (byte)(x + 8);
					expected3[expected_idx] = (byte)(x + 16);
					expected4[expected_idx] = (byte)(x + 24);
				}
				s += 32;
			}

			shake.ExtractBytesAll(output1, output2, output3, output4, 0);


			CollectionAssert.AreEqual(expected1, output1, "Output 1 did not match");
			CollectionAssert.AreEqual(expected2, output2, "Output 2 did not match");
			CollectionAssert.AreEqual(expected3, output3, "Output 3 did not match");
			CollectionAssert.AreEqual(expected4, output4, "Output 4 did not match");
		}
	}
}
