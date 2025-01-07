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

namespace PQnet.Digest {
	/// <summary>
	/// Implementation of SHAKE-128 Hash Algorithm
	/// </summary>
	public class Shake128 : KeccakBase {
		/// <summary>
		/// The rate of the SHAKE-128 algorithm
		/// </summary>
		public const int Shake128Rate = 168;

		/// <summary>
		/// Initializes a new instance of the <see cref="Shake128"/> class.
		/// </summary>
		public Shake128() {
			base.rate = Shake128Rate;
			base.prefix = 0x1f;
		}

		/// <summary>
		/// Compute the SHAKE-128 hash of the input data
		/// </summary>
		/// <param name="input">The data for which to compute the hash</param>
		/// <param name="outlen">The desired length of the hash</param>
		/// <returns>The SHAKE-128 hash for <paramref name="input"/></returns>
		public static byte[] HashData(byte[] input, int outlen = Shake128Rate) {
			Shake128 shake;
			byte[] result;
			int blocks;


			shake = new Shake128();
			result = new byte[outlen];

			shake.AbsorbOnce(input, input.Length);

			blocks = outlen / shake.rate;
			if (blocks > 0) {
				int out_pos;

				out_pos = shake.SqueezeBlocks(result, 0, blocks);
				shake.Squeeze(result, out_pos, outlen - out_pos);
				return result;
			}

			shake.Squeeze(result, 0, outlen);

			return result;
		}
	}
}
