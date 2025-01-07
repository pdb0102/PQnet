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
			byte[] reference;
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
			reference = new byte[max_outlen];
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
	}
}
