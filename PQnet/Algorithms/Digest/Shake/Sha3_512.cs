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
	/// Implementation of SHA3-512 Hash Algorithm
	/// </summary>
	public class Sha3_512 : KeccakBase {
		/// <summary>
		/// Initializes a new instance of the <see cref="Sha3_512"/> class.
		/// </summary>
		public Sha3_512() {
			base.rate = Sha3_512Rate;
			base.prefix = 0x06;
		}

		/// <summary>
		/// Compute the SHA3-512 hash of the input data
		/// </summary>
		/// <param name="input">The data for which to compute the hash</param>
		/// <returns>The SHA3-512 hash for <paramref name="input"/></returns>
		public static byte[] ComputeHash(byte[] input) {
			Sha3_512 shake;
			byte[] result;
			int blocks;

			shake = new Sha3_512();
			result = new byte[64];

			shake.AbsorbOnce(input, input.Length);

			blocks = 64 / shake.rate;
			if (blocks > 0) {
				int out_pos;

				out_pos = shake.SqueezeBlocks(result, 0, blocks);
				shake.Squeeze(result, out_pos, 64 - out_pos);
				return result;
			}

			shake.Squeeze(result, 0, 64);

			return result;
		}

		/// <summary>
		/// Compute the SHA3-512 hash of the input data
		/// </summary>
		/// <param name="input">The data for which to compute the hash</param>
		/// <param name="inlen">The number of bytes to absorb from <paramref name="input"/></param>
		/// <returns>The SHA3-512 hash for <paramref name="input"/></returns>
		public static byte[] ComputeHash(byte[] input, int inlen) {
			Sha3_512 shake;
			byte[] result;
			int blocks;

			shake = new Sha3_512();
			result = new byte[64];

			shake.AbsorbOnce(input, inlen);

			blocks = 64 / shake.rate;
			if (blocks > 0) {
				int out_pos;

				out_pos = shake.SqueezeBlocks(result, 0, blocks);
				shake.Squeeze(result, out_pos, 64 - out_pos);
				return result;
			}

			shake.Squeeze(result, 0, 64);

			return result;
		}
	}
}
