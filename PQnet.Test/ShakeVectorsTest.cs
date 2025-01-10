// MIT License
// 
// Copyright (c) 2025 Peter Dennis Bartok 
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

using PQnet.Digest;

namespace PQnet.test {
	[TestClass]
	public class ShakeVectorsTest {
		[TestMethod]
		[DataRow(false, "SHAKE.SHAKE128Monte.rsp", DisplayName = "SHAKE128 Monte Carlo")]
		[DataRow(true, "SHAKE.SHAKE256Monte.rsp", DisplayName = "SHAKE256 Monte Carlo")]
		public void ShakeNistMonteCarloVectors(bool use_shake256, string resource) {
			KeccakBase shake;
			RspFile.MonteCarlo montecarlo;
			string msg_txt;
			byte[] msg;
			byte[] output;
			int len;
			int outlen;
			int max_outlen;
			int min_outlen;
			int range;

			montecarlo = RspFile.LoadMonteCarlo(resource);

			msg_txt = montecarlo.Msg;
			min_outlen = montecarlo.MininumLength / 8;
			max_outlen = montecarlo.MaximumLength / 8;

			if (use_shake256) {
				shake = new Shake256();
			} else {
				shake = new Shake128();
			}

			output = new byte[max_outlen];
			len = 0;

			msg = msg_txt.HexToBytes();
			Array.Copy(msg, output, msg.Length);

			outlen = max_outlen;
			range = max_outlen - min_outlen + 1;

			for (int j = 0; j < 100; j++) {
				for (int i = 1; i < 1001; i++) {
					len = outlen;

					shake.Init();
					shake.AbsorbOnce(output, 16);
					shake.Squeeze(output, 0, len);
					if (len < 16) {
						Array.Fill(output, (byte)0, len, 16 - len);
					}
					outlen = min_outlen + (((output[len - 2] << 8) + output[len - 1]) % range);
				}

				Assert.AreEqual(montecarlo.Counts[j].Count, j, "Monte Carlo not ordered properly");
				Assert.AreEqual(montecarlo.Counts[j].OutputLen, len * 8, "Monte Carlo output length not the same");
				Assert.AreEqual(montecarlo.Counts[j].Output.ToLower(), output.ToHexString(0, len).ToLower(), "Monte Carlo message not the same");
			}
		}

		[TestMethod]
		[DataRow(224, "SHAKE.SHA3_224Monte.rsp", DisplayName = "SHA3-224 Monte Carlo")]
		[DataRow(256, "SHAKE.SHA3_256Monte.rsp", DisplayName = "SHA3-256 Monte Carlo")]
		[DataRow(384, "SHAKE.SHA3_384Monte.rsp", DisplayName = "SHA3-384 Monte Carlo")]
		[DataRow(512, "SHAKE.SHA3_512Monte.rsp", DisplayName = "SHA3-512 Monte Carlo")]
		public void Sha3NistMonteCarloVectors(int size, string resource) {
			KeccakBase shake;
			RspFile.MonteCarlo montecarlo;
			string msg_txt;
			byte[] msg;
			byte[] output;

			montecarlo = RspFile.LoadMonteCarlo(resource);

			msg_txt = montecarlo.Msg;

			switch (size) {
				case 224:
					shake = new Sha3_224();
					break;
				case 256:
					shake = new Sha3_256();
					break;
				case 384:
					shake = new Sha3_384();
					break;
				case 512:
					shake = new Sha3_512();
					break;
				default:
					Assert.Fail("Invalid size");
					return;
			}

			output = new byte[size / 8];

			msg = msg_txt.HexToBytes();
			Array.Copy(msg, output, msg.Length);

			for (int j = 0; j < 100; j++) {
				for (int i = 1; i < 1001; i++) {
					shake.Hash(output, output.Length, output, output.Length);
				}

				Assert.AreEqual(montecarlo.Counts[j].Count, j, "Monte Carlo not ordered properly");
				Assert.AreEqual(montecarlo.Counts[j].Output.ToLower(), output.ToHexString().ToLower(), "Monte Carlo message not the same");
			}
		}

		[TestMethod]
		[DataRow(false, "SHAKE.SHAKE128ShortMsg.rsp", DisplayName = "SHAKE128 Short")]
		[DataRow(false, "SHAKE.SHAKE128LongMsg.rsp", DisplayName = "SHAKE128 Long")]
		[DataRow(true, "SHAKE.SHAKE256ShortMsg.rsp", DisplayName = "SHAKE256 Short")]
		[DataRow(true, "SHAKE.SHAKE256LongMsg.rsp", DisplayName = "SHAKE256 Long")]
		public void ShakeNistHashVectors(bool use_shake256, string resource) {
			KeccakBase shake;
			RspFile.Hash hash;
			int outlen;
			byte[] outbuf;
			byte[] msg;

			hash = RspFile.LoadHash(resource);

			outlen = hash.OutputLen / 8;
			outbuf = new byte[outlen];

			if (use_shake256) {
				shake = new Shake256();
			} else {
				shake = new Shake128();
			}

			for (int i = 0; i < hash.Entries.Count; i++) {
				msg = hash.Entries[i].Msg.HexToBytes();
				shake.Init();
				shake.Hash(outbuf, outlen, msg, hash.Entries[i].Len / 8);
				Assert.AreEqual(hash.Entries[i].Output.ToLower(), outbuf.ToHexString().ToLower(), $"Hash message {i}, Len {msg.Length} not the same");
			}
		}

		[TestMethod]
		[DataRow(224, "SHAKE.SHA3_224ShortMsg.rsp", DisplayName = "SHA3-224 Short")]
		[DataRow(224, "SHAKE.SHA3_224LongMsg.rsp", DisplayName = "SHA3-224 Long")]
		[DataRow(256, "SHAKE.SHA3_256ShortMsg.rsp", DisplayName = "SHA3-256 Short")]
		[DataRow(256, "SHAKE.SHA3_256LongMsg.rsp", DisplayName = "SHA3-256 Long")]
		[DataRow(384, "SHAKE.SHA3_384ShortMsg.rsp", DisplayName = "SHA3-384 Short")]
		[DataRow(384, "SHAKE.SHA3_384LongMsg.rsp", DisplayName = "SHA3-384 Long")]
		[DataRow(512, "SHAKE.SHA3_512ShortMsg.rsp", DisplayName = "SHA3-512 Short")]
		[DataRow(512, "SHAKE.SHA3_512LongMsg.rsp", DisplayName = "SHA3-512 Long")]
		public void Sha3NistHashVectors(int size, string resource) {
			KeccakBase shake;
			RspFile.Hash hash;
			int outlen;
			byte[] outbuf;
			byte[] msg;

			hash = RspFile.LoadHash(resource);

			outlen = hash.OutputLen / 8;
			outbuf = new byte[outlen];

			switch (size) {
				case 224:
					shake = new Sha3_224();
					break;
				case 256:
					shake = new Sha3_256();
					break;
				case 384:
					shake = new Sha3_384();
					break;
				case 512:
					shake = new Sha3_512();
					break;
				default:
					Assert.Fail("Invalid size");
					return;
			}

			for (int i = 0; i < hash.Entries.Count; i++) {
				msg = hash.Entries[i].Msg.HexToBytes();
				shake.Init();
				shake.Hash(outbuf, outlen, msg, hash.Entries[i].Len / 8);
				Assert.AreEqual(hash.Entries[i].Output.ToLower(), outbuf.ToHexString().ToLower(), $"Hash message {i}, Len {msg.Length} not the same");
			}
		}

		[TestMethod]
		[DataRow(224, "SHAKE.SHA3_224ShortMsg.rsp", DisplayName = "SHA3-224 Short")]
		[DataRow(224, "SHAKE.SHA3_224LongMsg.rsp", DisplayName = "SHA3-224 Long")]
		[DataRow(256, "SHAKE.SHA3_256ShortMsg.rsp", DisplayName = "SHA3-256 Short")]
		[DataRow(256, "SHAKE.SHA3_256LongMsg.rsp", DisplayName = "SHA3-256 Long")]
		[DataRow(384, "SHAKE.SHA3_384ShortMsg.rsp", DisplayName = "SHA3-384 Short")]
		[DataRow(384, "SHAKE.SHA3_384LongMsg.rsp", DisplayName = "SHA3-384 Long")]
		[DataRow(512, "SHAKE.SHA3_512ShortMsg.rsp", DisplayName = "SHA3-512 Short")]
		[DataRow(512, "SHAKE.SHA3_512LongMsg.rsp", DisplayName = "SHA3-512 Long")]
		public void Sha3NistHashVectorsStaticAPI(int size, string resource) {
			RspFile.Hash hash;
			byte[] outbuf;
			byte[] msg;

			hash = RspFile.LoadHash(resource);

			for (int i = 0; i < hash.Entries.Count; i++) {
				msg = hash.Entries[i].Msg.HexToBytes();
				switch (size) {
					case 224:
						outbuf = Sha3_224.ComputeHash(msg, hash.Entries[i].Len / 8);
						break;
					case 256:
						outbuf = Sha3_256.ComputeHash(msg, hash.Entries[i].Len / 8);
						break;
					case 384:
						outbuf = Sha3_384.ComputeHash(msg, hash.Entries[i].Len / 8);
						break;
					case 512:
						outbuf = Sha3_512.ComputeHash(msg, hash.Entries[i].Len / 8);
						break;
					default:
						Assert.Fail("Invalid size");
						return;
				}
				Assert.AreEqual(hash.Entries[i].Output.ToLower(), outbuf.ToHexString().ToLower(), $"Hash message {i}, Len {msg.Length} not the same");
			}
		}

		[TestMethod]
		[DataRow(224, null, DisplayName = "SHA3-224 Parallel")]
		[DataRow(256, null, DisplayName = "SHA3-256 Parallel")]
		[DataRow(384, null, DisplayName = "SHA3-384 Parallel")]
		[DataRow(512, null, DisplayName = "SHA3-512 Parallel")]
		[DataRow(224, "0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f", DisplayName = "SHA3-224 Parallel seeded")]
		[DataRow(256, "0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f", DisplayName = "SHA3-256 Parallel seeded")]
		[DataRow(384, "0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f", DisplayName = "SHA3-384 Parallel seeded")]
		[DataRow(512, "0102030405060708090a0b0c0d0e0f0102030405060708090a0b0c0d0e0f", DisplayName = "SHA3-512 Parallel seeded")]
		public void Sha3_256_VS_Parallel_StaticAPI(int size, string seed_string) {
			byte[] one;
			byte[] two;
			byte[] three;
			byte[] four;
			byte[] seed;
			Tuple<byte[], byte[], byte[], byte[]> parallel_all;

			if (seed_string == null) {
				Rng.randombytes(out seed, size / 8);
			} else {
				seed = seed_string.HexToBytes();
			}

			// Reference calculation
			switch (size) {
				case 224:
					one = Sha3_224.ComputeHash(seed);
					two = Sha3_224.ComputeHash(one);
					three = Sha3_224.ComputeHash(two);
					four = Sha3_224.ComputeHash(three);
					parallel_all = Sha3_224x4.ComputeHash(seed, one, two, three);
					break;
				case 256:
					one = Sha3_256.ComputeHash(seed);
					two = Sha3_256.ComputeHash(one);
					three = Sha3_256.ComputeHash(two);
					four = Sha3_256.ComputeHash(three);
					parallel_all = Sha3_256x4.ComputeHash(seed, one, two, three);
					break;
				case 384:
					one = Sha3_384.ComputeHash(seed);
					two = Sha3_384.ComputeHash(one);
					three = Sha3_384.ComputeHash(two);
					four = Sha3_384.ComputeHash(three);
					parallel_all = Sha3_384x4.ComputeHash(seed, one, two, three);
					break;
				case 512:
					one = Sha3_512.ComputeHash(seed);
					two = Sha3_512.ComputeHash(one);
					three = Sha3_512.ComputeHash(two);
					four = Sha3_512.ComputeHash(three);
					parallel_all = Sha3_512x4.ComputeHash(seed, one, two, three);
					break;
				default:
					Assert.Fail("Invalid size");
					return;
			}

			CollectionAssert.AreEqual(one, parallel_all.Item1, $"Parallel Task 1 result wrong");
			CollectionAssert.AreEqual(two, parallel_all.Item2, $"Parallel Task 2 result wrong");
			CollectionAssert.AreEqual(three, parallel_all.Item3, $"Parallel Task 3 result wrong");
			CollectionAssert.AreEqual(four, parallel_all.Item4, $"Parallel Task 4 result wrong");
		}

		[TestMethod]
		[DataRow(true, 100, 2000, 1, DisplayName = "SHAKE128 Parallel 1 Iteration")]
		public void Shake_VS_Parallel(bool use_256, int absorb_length, int squeeze_length, int iterations) {
			byte[] seed;
			byte[] meh;
			byte[][] shake_out;
			byte[][] po;
			KeccakBase[] shake_base;
			KeccakBaseX4 shake_parallel_base;

			//Rng.randombytes(out seed, absorb_length);
			seed = new byte[absorb_length];

			meh = new byte[squeeze_length];

			if (!use_256) {
				shake_out = new byte[4][];
				po = new byte[4][];
				shake_base = new Shake128[4];
				for (int i = 0; i < 4; i++) {
					shake_base[i] = new Shake128();
					shake_out[i] = new byte[squeeze_length];
					po[i] = new byte[squeeze_length];
				}
				shake_parallel_base = new Shake128x4();
			} else {
				shake_out = new byte[4][];
				po = new byte[4][];
				shake_base = new Shake256[4];
				for (int i = 0; i < 4; i++) {
					shake_base[i] = new Shake256();
					shake_out[i] = new byte[squeeze_length];
					po[i] = new byte[squeeze_length];
				}
				shake_parallel_base = new Shake256x4();
			}

			shake_base[0].Absorb(seed, absorb_length);
			for (int i = 0; i < iterations; i++) {
				shake_base[0].FinalizeAbsorb();
				shake_base[0].Squeeze(shake_out[0], 0, squeeze_length);
				shake_base[1].Absorb(shake_out[0], absorb_length);
				shake_base[1].FinalizeAbsorb();
				shake_base[1].Squeeze(shake_out[1], 0, squeeze_length);
				shake_base[2].Absorb(shake_out[1], absorb_length);
				shake_base[2].FinalizeAbsorb();
				shake_base[2].Squeeze(shake_out[2], 0, squeeze_length);
				shake_base[3].Absorb(shake_out[2], absorb_length);
				shake_base[3].FinalizeAbsorb();
				shake_base[3].Squeeze(shake_out[3], 0, squeeze_length);
				shake_base[0].Absorb(shake_out[3], absorb_length);
			}
			shake_base[3].FinalizeAbsorb();
			shake_base[3].Squeeze(shake_out[0], 0, squeeze_length);

			for (int i = 0; i < iterations; i++) {
				shake_parallel_base.Sponge(seed, seed, seed, seed, po[0], po[0], po[0], po[0], squeeze_length, absorb_length);
				shake_parallel_base.Reset();
				//shake_parallel_base.Sponge(seed, po[0], seed, seed, meh, po[1], meh, meh, squeeze_length, absorb_length);
				shake_parallel_base.Sponge(po[0], po[0], po[0], po[0], po[1], po[1], po[1], po[1], squeeze_length, absorb_length);
				shake_parallel_base.Reset();
				shake_parallel_base.Sponge(seed, seed, po[1], seed, meh, meh, po[2], meh, squeeze_length, absorb_length);
				shake_parallel_base.Reset();
				shake_parallel_base.Sponge(seed, seed, seed, po[2], meh, meh, meh, po[3], squeeze_length, absorb_length);
				shake_parallel_base.Reset();
			}
			shake_parallel_base.Sponge(po[3], seed, seed, seed, po[0], po[1], po[2], po[3], squeeze_length, absorb_length);

			CollectionAssert.AreEqual(shake_out[0], po[0], $"Parallel Tasks result wrong");

		}
	}
}
