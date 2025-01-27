﻿// MIT License
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
	/// Implementation of SHA3-256 Hash Algorithm
	/// </summary>
	public class Sha3_256 : KeccakBase {
		/// <summary>
		/// Initializes a new instance of the <see cref="Sha3_256"/> class.
		/// </summary>
		public Sha3_256() {
			base.rate = Sha3_256Rate;
			base.prefix = 0x06;
		}

		/// <summary>
		/// Compute the SHA3-256 hash of the input data
		/// </summary>
		/// <param name="input">The data for which to compute the hash</param>
		/// <returns>The SHA3-256 hash for <paramref name="input"/></returns>
		public static byte[] ComputeHash(byte[] input) {
			Sha3_256 shake;
			byte[] result;
			int blocks;

			shake = new Sha3_256();
			result = new byte[32];

			shake.AbsorbOnce(input, input.Length);

			blocks = 32 / shake.rate;
			if (blocks > 0) {
				int out_pos;

				out_pos = shake.SqueezeBlocks(result, 0, blocks);
				shake.Squeeze(result, out_pos, 32 - out_pos);
				return result;
			}

			shake.Squeeze(result, 0, 32);

			return result;
		}

		/// <summary>
		/// Compute the SHA3-256 hash of the input data
		/// </summary>
		/// <param name="input">The data for which to compute the hash</param>
		/// <param name="inlen">The number of bytes to absorb from <paramref name="input"/></param>
		/// <returns>The SHA3-256 hash for <paramref name="input"/></returns>
		public static byte[] ComputeHash(byte[] input, int inlen) {
			Sha3_256 shake;
			byte[] result;
			int blocks;

			shake = new Sha3_256();
			result = new byte[32];

			shake.AbsorbOnce(input, inlen);

			blocks = 32 / shake.rate;
			if (blocks > 0) {
				int out_pos;

				out_pos = shake.SqueezeBlocks(result, 0, blocks);
				shake.Squeeze(result, out_pos, 32 - out_pos);
				return result;
			}

			shake.Squeeze(result, 0, 32);

			return result;
		}
	}
}
