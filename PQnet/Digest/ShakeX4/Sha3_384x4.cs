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

using System;

namespace PQnet.Digest {
	/// <summary>
	/// Implementation of SHA3-384 Hash Algorithm
	/// </summary>
	public class Sha3_384x4 : KeccakBaseX4 {
		/// <summary>
		/// Initializes a new instance of the <see cref="Sha3_384x4"/> class.
		/// </summary>
		public Sha3_384x4() : base(Sha3_384Rate, 384, 0x06) {
		}

		/// <summary>
		/// Calculate 4 SHA3-384 hashes in parallel.
		/// </summary>
		/// <param name="input1">The data to digest for hash 1</param>
		/// <param name="input2">The data to digest for hash 2</param>
		/// <param name="input3">The data to digest for hash 3</param>
		/// <param name="input4">The data to digest for hash 4</param>
		/// <returns>Tuple with four SHA3-384 hashes for <paramref name="input1"/>, <paramref name="input2"/>, <paramref name="input3"/> and <paramref name="input4"/></returns>
		public static Tuple<byte[], byte[], byte[], byte[]> ComputeHash(byte[] input1, byte[] input2, byte[] input3, byte[] input4) {
			KeccakBaseX4 shake;
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;

			shake = new KeccakBaseX4(KeccakBaseX4.Sha3_384Rate, 384, 0x06);

			output1 = new byte[384 / 8];
			output2 = new byte[384 / 8];
			output3 = new byte[384 / 8];
			output4 = new byte[384 / 8];

			shake.Sponge(input1, input2, input3, input4, output1, output2, output3, output4, 384 / 8);

			return new Tuple<byte[], byte[], byte[], byte[]>(output1, output2, output3, output4);
		}

		/// <summary>
		/// Calculate 4 SHA3-384 hashes in parallel.
		/// </summary>
		/// <param name="input1">The data to digest for hash 1</param>
		/// <param name="input2">The data to digest for hash 2</param>
		/// <param name="input3">The data to digest for hash 3</param>
		/// <param name="input4">The data to digest for hash 4</param>
		/// <param name="inlen">The number of bytes to absorb from each input</param>
		/// <returns>Tuple with four SHA3-384 hashes for <paramref name="input1"/>, <paramref name="input2"/>, <paramref name="input3"/> and <paramref name="input4"/></returns>
		public static Tuple<byte[], byte[], byte[], byte[]> ComputeHash(byte[] input1, byte[] input2, byte[] input3, byte[] input4, int inlen) {
			KeccakBaseX4 shake;
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;

			shake = new KeccakBaseX4(KeccakBaseX4.Sha3_384Rate, 384, 0x06);

			output1 = new byte[384 / 8];
			output2 = new byte[384 / 8];
			output3 = new byte[384 / 8];
			output4 = new byte[384 / 8];

			shake.Sponge(input1, input2, input3, input4, output1, output2, output3, output4, 384 / 8, inlen);

			return new Tuple<byte[], byte[], byte[], byte[]>(output1, output2, output3, output4);
		}
	}
}
