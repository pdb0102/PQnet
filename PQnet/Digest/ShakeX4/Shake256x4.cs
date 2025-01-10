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
	public class Shake256x4 : KeccakBaseX4 {
		/// <summary>
		/// Initializes a new instance of the <see cref="Shake256x4"/> class.
		/// </summary>
		public Shake256x4() : base(Shake256Rate, 256, 0x1f) {
		}

		/// <summary>
		/// Calculate 4 SHAKE256 hashes in parallel.
		/// </summary>
		/// <param name="input1">The data to digest for hash 1</param>
		/// <param name="input2">The data to digest for hash 2</param>
		/// <param name="input3">The data to digest for hash 3</param>
		/// <param name="input4">The data to digest for hash 4</param>
		/// <param name="outlen">The desired length of the hash</param>
		/// <returns>Tuple with four SHAKE-128 hashes for <paramref name="input1"/>, <paramref name="input2"/>, <paramref name="input3"/> and <paramref name="input4"/></returns>
		public static Tuple<byte[], byte[], byte[], byte[]> HashData(byte[] input1, byte[] input2, byte[] input3, byte[] input4, int outlen = 136) {
			KeccakBaseX4 shake;
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;

			shake = new KeccakBaseX4(KeccakBaseX4.Shake256Rate, 256, 0x1F);

			output1 = new byte[outlen];
			output2 = new byte[outlen];
			output3 = new byte[outlen];
			output4 = new byte[outlen];

			shake.Sponge(input1, input2, input3, input4, output1, output2, output3, output4, outlen);

			return new Tuple<byte[], byte[], byte[], byte[]>(output1, output2, output3, output4);
		}
	}
}
