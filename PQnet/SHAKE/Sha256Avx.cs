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

using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PQnet.Digest {
	internal class Sha256Parallel8 {
		private static Vector256<byte> mask = Vector256.Create((byte)0xc, 0xd, 0xe, 0xf, 0x8, 0x9, 0xa, 0xb, 0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3, 0xc, 0xd, 0xe, 0xf, 0x8, 0x9, 0xa, 0xb, 0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3);

		public class SHA256state {
			public SHA256state() {
				msgblocks = new byte[8 * 64];

				s = new Vector256<uint>[8];
			}

			public Vector256<uint>[] s;
			public byte[] msgblocks;
			public int datalen;
			public ulong msglen;
		}

		private static uint[] RC = {
			0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
			0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
			0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
			0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
			0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
			0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
			0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
			0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
			0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
			0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
			0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
			0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
			0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
			0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
			0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
			0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
		};

		private static void transpose(Vector256<uint>[] s, int s_offset) {
			Vector256<uint>[] tmp0;
			Vector256<uint>[] tmp1;

			tmp0 = new Vector256<uint>[8];
			tmp1 = new Vector256<uint>[8];

			tmp0[0] = Avx2.UnpackLow(s[s_offset + 0], s[s_offset + 1]);
			tmp0[1] = Avx2.UnpackHigh(s[s_offset + 0], s[s_offset + 1]);
			tmp0[2] = Avx2.UnpackLow(s[s_offset + 2], s[s_offset + 3]);
			tmp0[3] = Avx2.UnpackHigh(s[s_offset + 2], s[s_offset + 3]);
			tmp0[4] = Avx2.UnpackLow(s[s_offset + 4], s[s_offset + 5]);
			tmp0[5] = Avx2.UnpackHigh(s[s_offset + 4], s[s_offset + 5]);
			tmp0[6] = Avx2.UnpackLow(s[s_offset + 6], s[s_offset + 7]);
			tmp0[7] = Avx2.UnpackHigh(s[s_offset + 6], s[s_offset + 7]);
			tmp1[0] = Avx2.UnpackLow(tmp0[0], tmp0[2]);
			tmp1[1] = Avx2.UnpackHigh(tmp0[0], tmp0[2]);
			tmp1[2] = Avx2.UnpackLow(tmp0[1], tmp0[3]);
			tmp1[3] = Avx2.UnpackHigh(tmp0[1], tmp0[3]);
			tmp1[4] = Avx2.UnpackLow(tmp0[4], tmp0[6]);
			tmp1[5] = Avx2.UnpackHigh(tmp0[4], tmp0[6]);
			tmp1[6] = Avx2.UnpackLow(tmp0[5], tmp0[7]);
			tmp1[7] = Avx2.UnpackHigh(tmp0[5], tmp0[7]);
			s[s_offset + 0] = Avx2.Permute2x128(tmp1[0], tmp1[4], 0x20);
			s[s_offset + 1] = Avx2.Permute2x128(tmp1[1], tmp1[5], 0x20);
			s[s_offset + 2] = Avx2.Permute2x128(tmp1[2], tmp1[6], 0x20);
			s[s_offset + 3] = Avx2.Permute2x128(tmp1[3], tmp1[7], 0x20);
			s[s_offset + 4] = Avx2.Permute2x128(tmp1[0], tmp1[4], 0x31);
			s[s_offset + 5] = Avx2.Permute2x128(tmp1[1], tmp1[5], 0x31);
			s[s_offset + 6] = Avx2.Permute2x128(tmp1[2], tmp1[6], 0x31);
			s[s_offset + 7] = Avx2.Permute2x128(tmp1[3], tmp1[7], 0x31);
		}

		public static void sha256_init8x(SHA256state ctx) {
			ctx.s[0] = Vector256.Create(0x6a09e667u, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667, 0x6a09e667);
			ctx.s[1] = Vector256.Create(0xbb67ae85u, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85, 0xbb67ae85);
			ctx.s[2] = Vector256.Create(0x3c6ef372u, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372, 0x3c6ef372);
			ctx.s[3] = Vector256.Create(0xa54ff53au, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a, 0xa54ff53a);
			ctx.s[4] = Vector256.Create(0x510e527fu, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f, 0x510e527f);
			ctx.s[5] = Vector256.Create(0x9b05688cu, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c, 0x9b05688c);
			ctx.s[6] = Vector256.Create(0x1f83d9abu, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab, 0x1f83d9ab);
			ctx.s[7] = Vector256.Create(0x5be0cd19u, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19, 0x5be0cd19);

			ctx.datalen = 0;
			ctx.msglen = 0;
		}

		public static void sha256_final8x(SHA256state ctx, byte[] out0, byte[] out1, byte[] out2, byte[] out3, byte[] out4, byte[] out5, byte[] out6, byte[] out7) {
			int curlen;

			// Padding
			if (ctx.datalen < 56) {
				for (int i = 0; i < 8; i++) {
					curlen = ctx.datalen;
					ctx.msgblocks[(64 * i) + curlen++] = 0x80;
					while (curlen < 64) {
						ctx.msgblocks[(64 * i) + curlen++] = 0x00;
					}
				}
			} else {
				for (int i = 0; i < 8; ++i) {
					curlen = ctx.datalen;
					ctx.msgblocks[(64 * i) + curlen++] = 0x80;
					while (curlen < 64) {
						ctx.msgblocks[(64 * i) + curlen++] = 0x00;
					}
				}
				sha256_transform8x(ctx, ctx.msgblocks);
				Array.Clear(ctx.msgblocks, 0, 8 * 64);
			}

			// Add length of the message to each block
			ctx.msglen += (ulong)ctx.datalen * 8;
			for (int i = 0; i < 8; i++) {
				ctx.msgblocks[(64 * i) + 63] = (byte)ctx.msglen;
				ctx.msgblocks[(64 * i) + 62] = (byte)(ctx.msglen >> 8);
				ctx.msgblocks[(64 * i) + 61] = (byte)(ctx.msglen >> 16);
				ctx.msgblocks[(64 * i) + 60] = (byte)(ctx.msglen >> 24);
				ctx.msgblocks[(64 * i) + 59] = (byte)(ctx.msglen >> 32);
				ctx.msgblocks[(64 * i) + 58] = (byte)(ctx.msglen >> 40);
				ctx.msgblocks[(64 * i) + 57] = (byte)(ctx.msglen >> 48);
				ctx.msgblocks[(64 * i) + 56] = (byte)(ctx.msglen >> 56);
			}
			sha256_transform8x(ctx, ctx.msgblocks);

			// Compute final hash output
			transpose(ctx.s, 0);

			// Store Hash value
			Store(out0, 0, ByteSwap(ctx.s[0], mask));
			Store(out1, 0, ByteSwap(ctx.s[1], mask));
			Store(out2, 0, ByteSwap(ctx.s[2], mask));
			Store(out3, 0, ByteSwap(ctx.s[3], mask));
			Store(out4, 0, ByteSwap(ctx.s[4], mask));
			Store(out5, 0, ByteSwap(ctx.s[5], mask));
			Store(out6, 0, ByteSwap(ctx.s[6], mask));
			Store(out7, 0, ByteSwap(ctx.s[7], mask));
		}

		public static void sha256_transform8x(SHA256state ctx, byte[] msgblocks) {
			Vector256<uint>[] s;
			Vector256<uint>[] w;

			s = new Vector256<uint>[8];
			w = new Vector256<uint>[64];

			// Load words and transform data correctly
			w[0] = ByteSwap(Load(msgblocks, 64 * 0), mask);
			w[0 + 8] = ByteSwap(Load(msgblocks, (64 * 0) + 32), mask);
			w[1] = ByteSwap(Load(msgblocks, 64 * 1), mask);
			w[1 + 8] = ByteSwap(Load(msgblocks, (64 * 1) + 32), mask);
			w[2] = ByteSwap(Load(msgblocks, 64 * 2), mask);
			w[2 + 8] = ByteSwap(Load(msgblocks, (64 * 2) + 32), mask);
			w[3] = ByteSwap(Load(msgblocks, 64 * 3), mask);
			w[3 + 8] = ByteSwap(Load(msgblocks, (64 * 3) + 32), mask);
			w[4] = ByteSwap(Load(msgblocks, 64 * 4), mask);
			w[4 + 8] = ByteSwap(Load(msgblocks, (64 * 4) + 32), mask);
			w[5] = ByteSwap(Load(msgblocks, 64 * 5), mask);
			w[5 + 8] = ByteSwap(Load(msgblocks, (64 * 5) + 32), mask);
			w[6] = ByteSwap(Load(msgblocks, 64 * 6), mask);
			w[6 + 8] = ByteSwap(Load(msgblocks, (64 * 6) + 32), mask);
			w[7] = ByteSwap(Load(msgblocks, 64 * 7), mask);
			w[7 + 8] = ByteSwap(Load(msgblocks, (64 * 7) + 32), mask);

			transpose(w, 0);
			transpose(w, 8);

			// Initial State
			s[0] = ctx.s[0];
			s[1] = ctx.s[1];
			s[2] = ctx.s[2];
			s[3] = ctx.s[3];
			s[4] = ctx.s[4];
			s[5] = ctx.s[5];
			s[6] = ctx.s[6];
			s[7] = ctx.s[7];


			SHA256Round_AVX(s, 0, 1, 2, 3, 4, 5, 6, 7, 0, w[0]);
			SHA256Round_AVX(s, 7, 0, 1, 2, 3, 4, 5, 6, 1, w[1]);
			SHA256Round_AVX(s, 6, 7, 0, 1, 2, 3, 4, 5, 2, w[2]);
			SHA256Round_AVX(s, 5, 6, 7, 0, 1, 2, 3, 4, 3, w[3]);
			SHA256Round_AVX(s, 4, 5, 6, 7, 0, 1, 2, 3, 4, w[4]);
			SHA256Round_AVX(s, 3, 4, 5, 6, 7, 0, 1, 2, 5, w[5]);
			SHA256Round_AVX(s, 2, 3, 4, 5, 6, 7, 0, 1, 6, w[6]);
			SHA256Round_AVX(s, 1, 2, 3, 4, 5, 6, 7, 0, 7, w[7]);
			SHA256Round_AVX(s, 0, 1, 2, 3, 4, 5, 6, 7, 8, w[8]);
			SHA256Round_AVX(s, 7, 0, 1, 2, 3, 4, 5, 6, 9, w[9]);
			SHA256Round_AVX(s, 6, 7, 0, 1, 2, 3, 4, 5, 10, w[10]);
			SHA256Round_AVX(s, 5, 6, 7, 0, 1, 2, 3, 4, 11, w[11]);
			SHA256Round_AVX(s, 4, 5, 6, 7, 0, 1, 2, 3, 12, w[12]);
			SHA256Round_AVX(s, 3, 4, 5, 6, 7, 0, 1, 2, 13, w[13]);
			SHA256Round_AVX(s, 2, 3, 4, 5, 6, 7, 0, 1, 14, w[14]);
			SHA256Round_AVX(s, 1, 2, 3, 4, 5, 6, 7, 0, 15, w[15]);
			w[16] = Add4(WSigma1_AVX(w[14]), w[0], w[9], WSigma0_AVX(w[1]));
			SHA256Round_AVX(s, 0, 1, 2, 3, 4, 5, 6, 7, 16, w[16]);
			w[17] = Add4(WSigma1_AVX(w[15]), w[1], w[10], WSigma0_AVX(w[2]));
			SHA256Round_AVX(s, 7, 0, 1, 2, 3, 4, 5, 6, 17, w[17]);
			w[18] = Add4(WSigma1_AVX(w[16]), w[2], w[11], WSigma0_AVX(w[3]));
			SHA256Round_AVX(s, 6, 7, 0, 1, 2, 3, 4, 5, 18, w[18]);
			w[19] = Add4(WSigma1_AVX(w[17]), w[3], w[12], WSigma0_AVX(w[4]));
			SHA256Round_AVX(s, 5, 6, 7, 0, 1, 2, 3, 4, 19, w[19]);
			w[20] = Add4(WSigma1_AVX(w[18]), w[4], w[13], WSigma0_AVX(w[5]));
			SHA256Round_AVX(s, 4, 5, 6, 7, 0, 1, 2, 3, 20, w[20]);
			w[21] = Add4(WSigma1_AVX(w[19]), w[5], w[14], WSigma0_AVX(w[6]));
			SHA256Round_AVX(s, 3, 4, 5, 6, 7, 0, 1, 2, 21, w[21]);
			w[22] = Add4(WSigma1_AVX(w[20]), w[6], w[15], WSigma0_AVX(w[7]));
			SHA256Round_AVX(s, 2, 3, 4, 5, 6, 7, 0, 1, 22, w[22]);
			w[23] = Add4(WSigma1_AVX(w[21]), w[7], w[16], WSigma0_AVX(w[8]));
			SHA256Round_AVX(s, 1, 2, 3, 4, 5, 6, 7, 0, 23, w[23]);
			w[24] = Add4(WSigma1_AVX(w[22]), w[8], w[17], WSigma0_AVX(w[9]));
			SHA256Round_AVX(s, 0, 1, 2, 3, 4, 5, 6, 7, 24, w[24]);
			w[25] = Add4(WSigma1_AVX(w[23]), w[9], w[18], WSigma0_AVX(w[10]));
			SHA256Round_AVX(s, 7, 0, 1, 2, 3, 4, 5, 6, 25, w[25]);
			w[26] = Add4(WSigma1_AVX(w[24]), w[10], w[19], WSigma0_AVX(w[11]));
			SHA256Round_AVX(s, 6, 7, 0, 1, 2, 3, 4, 5, 26, w[26]);
			w[27] = Add4(WSigma1_AVX(w[25]), w[11], w[20], WSigma0_AVX(w[12]));
			SHA256Round_AVX(s, 5, 6, 7, 0, 1, 2, 3, 4, 27, w[27]);
			w[28] = Add4(WSigma1_AVX(w[26]), w[12], w[21], WSigma0_AVX(w[13]));
			SHA256Round_AVX(s, 4, 5, 6, 7, 0, 1, 2, 3, 28, w[28]);
			w[29] = Add4(WSigma1_AVX(w[27]), w[13], w[22], WSigma0_AVX(w[14]));
			SHA256Round_AVX(s, 3, 4, 5, 6, 7, 0, 1, 2, 29, w[29]);
			w[30] = Add4(WSigma1_AVX(w[28]), w[14], w[23], WSigma0_AVX(w[15]));
			SHA256Round_AVX(s, 2, 3, 4, 5, 6, 7, 0, 1, 30, w[30]);
			w[31] = Add4(WSigma1_AVX(w[29]), w[15], w[24], WSigma0_AVX(w[16]));
			SHA256Round_AVX(s, 1, 2, 3, 4, 5, 6, 7, 0, 31, w[31]);
			w[32] = Add4(WSigma1_AVX(w[30]), w[16], w[25], WSigma0_AVX(w[17]));
			SHA256Round_AVX(s, 0, 1, 2, 3, 4, 5, 6, 7, 32, w[32]);
			w[33] = Add4(WSigma1_AVX(w[31]), w[17], w[26], WSigma0_AVX(w[18]));
			SHA256Round_AVX(s, 7, 0, 1, 2, 3, 4, 5, 6, 33, w[33]);
			w[34] = Add4(WSigma1_AVX(w[32]), w[18], w[27], WSigma0_AVX(w[19]));
			SHA256Round_AVX(s, 6, 7, 0, 1, 2, 3, 4, 5, 34, w[34]);
			w[35] = Add4(WSigma1_AVX(w[33]), w[19], w[28], WSigma0_AVX(w[20]));
			SHA256Round_AVX(s, 5, 6, 7, 0, 1, 2, 3, 4, 35, w[35]);
			w[36] = Add4(WSigma1_AVX(w[34]), w[20], w[29], WSigma0_AVX(w[21]));
			SHA256Round_AVX(s, 4, 5, 6, 7, 0, 1, 2, 3, 36, w[36]);
			w[37] = Add4(WSigma1_AVX(w[35]), w[21], w[30], WSigma0_AVX(w[22]));
			SHA256Round_AVX(s, 3, 4, 5, 6, 7, 0, 1, 2, 37, w[37]);
			w[38] = Add4(WSigma1_AVX(w[36]), w[22], w[31], WSigma0_AVX(w[23]));
			SHA256Round_AVX(s, 2, 3, 4, 5, 6, 7, 0, 1, 38, w[38]);
			w[39] = Add4(WSigma1_AVX(w[37]), w[23], w[32], WSigma0_AVX(w[24]));
			SHA256Round_AVX(s, 1, 2, 3, 4, 5, 6, 7, 0, 39, w[39]);
			w[40] = Add4(WSigma1_AVX(w[38]), w[24], w[33], WSigma0_AVX(w[25]));
			SHA256Round_AVX(s, 0, 1, 2, 3, 4, 5, 6, 7, 40, w[40]);
			w[41] = Add4(WSigma1_AVX(w[39]), w[25], w[34], WSigma0_AVX(w[26]));
			SHA256Round_AVX(s, 7, 0, 1, 2, 3, 4, 5, 6, 41, w[41]);
			w[42] = Add4(WSigma1_AVX(w[40]), w[26], w[35], WSigma0_AVX(w[27]));
			SHA256Round_AVX(s, 6, 7, 0, 1, 2, 3, 4, 5, 42, w[42]);
			w[43] = Add4(WSigma1_AVX(w[41]), w[27], w[36], WSigma0_AVX(w[28]));
			SHA256Round_AVX(s, 5, 6, 7, 0, 1, 2, 3, 4, 43, w[43]);
			w[44] = Add4(WSigma1_AVX(w[42]), w[28], w[37], WSigma0_AVX(w[29]));
			SHA256Round_AVX(s, 4, 5, 6, 7, 0, 1, 2, 3, 44, w[44]);
			w[45] = Add4(WSigma1_AVX(w[43]), w[29], w[38], WSigma0_AVX(w[30]));
			SHA256Round_AVX(s, 3, 4, 5, 6, 7, 0, 1, 2, 45, w[45]);
			w[46] = Add4(WSigma1_AVX(w[44]), w[30], w[39], WSigma0_AVX(w[31]));
			SHA256Round_AVX(s, 2, 3, 4, 5, 6, 7, 0, 1, 46, w[46]);
			w[47] = Add4(WSigma1_AVX(w[45]), w[31], w[40], WSigma0_AVX(w[32]));
			SHA256Round_AVX(s, 1, 2, 3, 4, 5, 6, 7, 0, 47, w[47]);
			w[48] = Add4(WSigma1_AVX(w[46]), w[32], w[41], WSigma0_AVX(w[33]));
			SHA256Round_AVX(s, 0, 1, 2, 3, 4, 5, 6, 7, 48, w[48]);
			w[49] = Add4(WSigma1_AVX(w[47]), w[33], w[42], WSigma0_AVX(w[34]));
			SHA256Round_AVX(s, 7, 0, 1, 2, 3, 4, 5, 6, 49, w[49]);
			w[50] = Add4(WSigma1_AVX(w[48]), w[34], w[43], WSigma0_AVX(w[35]));
			SHA256Round_AVX(s, 6, 7, 0, 1, 2, 3, 4, 5, 50, w[50]);
			w[51] = Add4(WSigma1_AVX(w[49]), w[35], w[44], WSigma0_AVX(w[36]));
			SHA256Round_AVX(s, 5, 6, 7, 0, 1, 2, 3, 4, 51, w[51]);
			w[52] = Add4(WSigma1_AVX(w[50]), w[36], w[45], WSigma0_AVX(w[37]));
			SHA256Round_AVX(s, 4, 5, 6, 7, 0, 1, 2, 3, 52, w[52]);
			w[53] = Add4(WSigma1_AVX(w[51]), w[37], w[46], WSigma0_AVX(w[38]));
			SHA256Round_AVX(s, 3, 4, 5, 6, 7, 0, 1, 2, 53, w[53]);
			w[54] = Add4(WSigma1_AVX(w[52]), w[38], w[47], WSigma0_AVX(w[39]));
			SHA256Round_AVX(s, 2, 3, 4, 5, 6, 7, 0, 1, 54, w[54]);
			w[55] = Add4(WSigma1_AVX(w[53]), w[39], w[48], WSigma0_AVX(w[40]));
			SHA256Round_AVX(s, 1, 2, 3, 4, 5, 6, 7, 0, 55, w[55]);
			w[56] = Add4(WSigma1_AVX(w[54]), w[40], w[49], WSigma0_AVX(w[41]));
			SHA256Round_AVX(s, 0, 1, 2, 3, 4, 5, 6, 7, 56, w[56]);
			w[57] = Add4(WSigma1_AVX(w[55]), w[41], w[50], WSigma0_AVX(w[42]));
			SHA256Round_AVX(s, 7, 0, 1, 2, 3, 4, 5, 6, 57, w[57]);
			w[58] = Add4(WSigma1_AVX(w[56]), w[42], w[51], WSigma0_AVX(w[43]));
			SHA256Round_AVX(s, 6, 7, 0, 1, 2, 3, 4, 5, 58, w[58]);
			w[59] = Add4(WSigma1_AVX(w[57]), w[43], w[52], WSigma0_AVX(w[44]));
			SHA256Round_AVX(s, 5, 6, 7, 0, 1, 2, 3, 4, 59, w[59]);
			w[60] = Add4(WSigma1_AVX(w[58]), w[44], w[53], WSigma0_AVX(w[45]));
			SHA256Round_AVX(s, 4, 5, 6, 7, 0, 1, 2, 3, 60, w[60]);
			w[61] = Add4(WSigma1_AVX(w[59]), w[45], w[54], WSigma0_AVX(w[46]));
			SHA256Round_AVX(s, 3, 4, 5, 6, 7, 0, 1, 2, 61, w[61]);
			w[62] = Add4(WSigma1_AVX(w[60]), w[46], w[55], WSigma0_AVX(w[47]));
			SHA256Round_AVX(s, 2, 3, 4, 5, 6, 7, 0, 1, 62, w[62]);
			w[63] = Add4(WSigma1_AVX(w[61]), w[47], w[56], WSigma0_AVX(w[48]));
			SHA256Round_AVX(s, 1, 2, 3, 4, 5, 6, 7, 0, 63, w[63]);

			// Feed Forward
			ctx.s[0] = Avx2.Add(s[0], ctx.s[0]);
			ctx.s[1] = Avx2.Add(s[1], ctx.s[1]);
			ctx.s[2] = Avx2.Add(s[2], ctx.s[2]);
			ctx.s[3] = Avx2.Add(s[3], ctx.s[3]);
			ctx.s[4] = Avx2.Add(s[4], ctx.s[4]);
			ctx.s[5] = Avx2.Add(s[5], ctx.s[5]);
			ctx.s[6] = Avx2.Add(s[6], ctx.s[6]);
			ctx.s[7] = Avx2.Add(s[7], ctx.s[7]);
		}
		public static void perform_sha256x8(out byte[] out0, out byte[] out1, out byte[] out2, out byte[] out3, out byte[] out4, out byte[] out5, out byte[] out6, out byte[] out7, byte[] in0, byte[] in1, byte[] in2, byte[] in3, byte[] in4, byte[] in5, byte[] in6, byte[] in7) {
			int i;
			int bytes_to_copy;
			byte[] combined;
			int inlen;
			SHA256state ctx;

			ctx = new SHA256state();
			sha256_init8x(ctx);

			inlen = in0.Length;

			combined = new byte[8 * inlen];
			Array.Copy(in0, 0, combined, 0 * inlen, inlen);
			Array.Copy(in1, 0, combined, 1 * inlen, inlen);
			Array.Copy(in2, 0, combined, 2 * inlen, inlen);
			Array.Copy(in3, 0, combined, 3 * inlen, inlen);
			Array.Copy(in4, 0, combined, 4 * inlen, inlen);
			Array.Copy(in5, 0, combined, 5 * inlen, inlen);
			Array.Copy(in6, 0, combined, 6 * inlen, inlen);
			Array.Copy(in7, 0, combined, 7 * inlen, inlen);

			i = 0;
			while (inlen - i >= 64) {
				sha256_transform8x(ctx, combined);
				i += 64;
				ctx.msglen += 512;
			}

			bytes_to_copy = inlen - i;

			Array.Copy(in0, i, ctx.msgblocks, 64 * 0, bytes_to_copy);
			Array.Copy(in1, i, ctx.msgblocks, 64 * 1, bytes_to_copy);
			Array.Copy(in2, i, ctx.msgblocks, 64 * 2, bytes_to_copy);
			Array.Copy(in3, i, ctx.msgblocks, 64 * 3, bytes_to_copy);
			Array.Copy(in4, i, ctx.msgblocks, 64 * 4, bytes_to_copy);
			Array.Copy(in5, i, ctx.msgblocks, 64 * 5, bytes_to_copy);
			Array.Copy(in6, i, ctx.msgblocks, 64 * 6, bytes_to_copy);
			Array.Copy(in7, i, ctx.msgblocks, 64 * 7, bytes_to_copy);

			ctx.datalen = bytes_to_copy;

			out0 = new byte[32];
			out1 = new byte[32];
			out2 = new byte[32];
			out3 = new byte[32];
			out4 = new byte[32];
			out5 = new byte[32];
			out6 = new byte[32];
			out7 = new byte[32];
			sha256_final8x(ctx, out0, out1, out2, out3, out4, out5, out6, out7);
		}

		private static Vector256<uint> RotateRight6(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 6), Avx2.ShiftLeftLogical(value, 32 - 6));
		}

		private static Vector256<uint> RotateRight11(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 11), Avx2.ShiftLeftLogical(value, 32 - 11));
		}

		private static Vector256<uint> RotateRight25(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 25), Avx2.ShiftLeftLogical(value, 32 - 25));
		}

		private static Vector256<uint> RotateRight2(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 2), Avx2.ShiftLeftLogical(value, 32 - 2));
		}

		private static Vector256<uint> RotateRight13(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 13), Avx2.ShiftLeftLogical(value, 32 - 13));
		}
		private static Vector256<uint> RotateRight22(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 22), Avx2.ShiftLeftLogical(value, 32 - 22));
		}

		private static Vector256<uint> RotateRight17(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 17), Avx2.ShiftLeftLogical(value, 32 - 17));
		}

		private static Vector256<uint> RotateRight19(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 19), Avx2.ShiftLeftLogical(value, 32 - 19));
		}

		private static Vector256<uint> RotateRight7(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 7), Avx2.ShiftLeftLogical(value, 32 - 7));
		}

		private static Vector256<uint> RotateRight18(Vector256<uint> value) {
			return Avx2.Or(Avx2.ShiftRightLogical(value, 18), Avx2.ShiftLeftLogical(value, 32 - 18));
		}


		private static Vector256<uint> Load(uint[] data, int offset) {
			return Vector256.Create(data[offset], data[offset + 1], data[offset + 2], data[offset + 3], data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7]);
		}

		private static Vector256<uint> Load(byte[] data, int offset) {
			return Vector256.Create(
				data[offset + 0],
				data[offset + 1],
				data[offset + 2],
				data[offset + 3],
				data[offset + 4],
				data[offset + 5],
				data[offset + 6],
				data[offset + 7],
				data[offset + 8],
				data[offset + 9],
				data[offset + 10],
				data[offset + 11],
				data[offset + 12],
				data[offset + 13],
				data[offset + 14],
				data[offset + 15],
				data[offset + 16],
				data[offset + 17],
				data[offset + 18],
				data[offset + 19],
				data[offset + 20],
				data[offset + 21],
				data[offset + 22],
				data[offset + 23],
				data[offset + 24],
				data[offset + 25],
				data[offset + 26],
				data[offset + 27],
				data[offset + 28],
				data[offset + 29],
				data[offset + 30],
				data[offset + 31]
			).AsUInt32();
		}

		private static void Store(byte[] data, int offset, Vector256<uint> value) {
			Vector256<byte> bytes;

			bytes = value.AsByte();
			for (int i = 0; i < 32; i++) {
				data[offset + i] = bytes.GetElement(i);
			}
		}

		private static Vector256<uint> Not(Vector256<uint> value) {
			return Avx2.Xor(value, Vector256.Create(uint.MaxValue, uint.MaxValue, uint.MaxValue, uint.MaxValue, uint.MaxValue, uint.MaxValue, uint.MaxValue, uint.MaxValue));
		}

		private static Vector256<uint> Ch_AVX(Vector256<uint> x, Vector256<uint> y, Vector256<uint> z) {
			return Avx2.Xor(Avx2.And(x, y), Avx2.AndNot(x, z));
		}

		private static Vector256<uint> Maj_AVX(Vector256<uint> x, Vector256<uint> y, Vector256<uint> z) {
			return Avx2.Xor(Avx2.Xor(Avx2.And(x, y), Avx2.And(x, z)), Avx2.And(y, z));
		}

		private static Vector256<uint> Sigma1_AVX(Vector256<uint> x) {
			return Avx2.Xor(Avx2.Xor(RotateRight6(x), RotateRight11(x)), RotateRight25(x));
		}

		private static Vector256<uint> Sigma0_AVX(Vector256<uint> x) {
			return Avx2.Xor(Avx2.Xor(RotateRight2(x), RotateRight13(x)), RotateRight22(x));
		}

		private static Vector256<uint> WSigma1_AVX(Vector256<uint> x) {
			return Avx2.Xor(Avx2.Xor(RotateRight17(x), RotateRight19(x)), Avx2.ShiftRightLogical(x, 10));
		}

		private static Vector256<uint> WSigma0_AVX(Vector256<uint> x) {
			return Avx2.Xor(Avx2.Xor(RotateRight7(x), RotateRight18(x)), Avx2.ShiftRightLogical(x, 3));
		}

		private static Vector256<uint> Add3(Vector256<uint> a, Vector256<uint> b, Vector256<uint> c) {
			return Avx2.Add(Avx2.Add(a, b), c);
		}

		private static Vector256<uint> Add4(Vector256<uint> a, Vector256<uint> b, Vector256<uint> c, Vector256<uint> d) {
			return Avx2.Add(Avx2.Add(Avx2.Add(a, b), c), d);
		}

		private static Vector256<uint> Add5(Vector256<uint> a, Vector256<uint> b, Vector256<uint> c, Vector256<uint> d, Vector256<uint> e) {
			return Avx2.Add(Avx2.Add(Avx2.Add(Avx2.Add(a, b), c), d), e);
		}

		private static void SHA256Round_AVX(Vector256<uint>[] s, int a, int b, int c, int d, int e, int f, int g, int h, int rc, Vector256<uint> w) {
			Vector256<uint> T0;
			Vector256<uint> T1;

			T0 = Add5(s[h], Sigma1_AVX(s[e]), Ch_AVX(s[e], s[f], s[g]), Vector256.Create(RC[rc]), w);
			s[d] = Avx2.Add(s[d], T0);

			T1 = Avx2.Add(Sigma0_AVX(s[a]), Maj_AVX(s[a], s[b], s[c]));
			s[h] = Avx2.Add(T0, T1);
		}

		private static Vector256<uint> ByteSwap(Vector256<uint> value, Vector256<byte> mask) {
			Vector256<byte> a;
			Vector256<byte> b;

			a = value.AsByte();
			b = Vector256.Create((byte)0xc, 0xd, 0xe, 0xf, 0x8, 0x9, 0xa, 0xb, 0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3, 0xc, 0xd, 0xe, 0xf, 0x8, 0x9, 0xa, 0xb, 0x4, 0x5, 0x6, 0x7, 0x0, 0x1, 0x2, 0x3);
			return Avx2.Shuffle(a, b).AsUInt32();
		}

	}
}
