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

namespace PQnet.Digest {
	/// <summary>
	/// A SIMD-optimized implementation of SHAKE128, SHAKE256, SHA3-256, and SHA3-512 that calculates 4 hashes in parallel.
	/// </summary>
	public partial class ShakeX4 {
		/// <summary>
		/// The SHAKE128 lane size in bytes.
		/// </summary>
		public const int Shake128Rate = 168;

		/// <summary>
		/// The SHAKE256 lane size in bytes.
		/// </summary>
		public const int Shake256Rate = 136;

		/// <summary>
		/// The SHA3-224 lane size in bytes.
		/// </summary>
		public const int Sha3_224Rate = 144;

		/// <summary>
		/// The SHA3-256 lane size in bytes.
		/// </summary>
		public const int Sha3_256Rate = 136;

		/// <summary>
		/// The SHA3-384 lane size in bytes.
		/// </summary>
		public const int Sha3_384Rate = 104;

		/// <summary>
		/// The SHA3-512 lane size in bytes.
		/// </summary>
		public const int Sha3_512Rate = 72;

		/// <summary>
		/// Calculate 4 SHAKE128 hashes in parallel.
		/// </summary>
		/// <param name="input1">The data to digest for hash 1</param>
		/// <param name="input2">The data to digest for hash 2</param>
		/// <param name="input3">The data to digest for hash 3</param>
		/// <param name="input4">The data to digest for hash 4</param>
		/// <param name="outlen">The desired length of the hash</param>
		/// <returns>A 4 byte[] tuple with the calcuated hashes</returns>
		public static Tuple<byte[], byte[], byte[], byte[]> Shake128(byte[] input1, byte[] input2, byte[] input3, byte[] input4, int outlen = 168) {
			ShakeX4 shake;
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;

			shake = new ShakeX4(ShakeX4.Shake128Rate, 128, 0x1F);

			output1 = new byte[outlen];
			output2 = new byte[outlen];
			output3 = new byte[outlen];
			output4 = new byte[outlen];

			shake.Sponge(input1, input2, input3, input4, output1, output2, output3, output4, outlen);

			return new Tuple<byte[], byte[], byte[], byte[]>(output1, output2, output3, output4);
		}

		/// <summary>
		/// Calculate 4 SHAKE256 hashes in parallel.
		/// </summary>
		/// <param name="input1">The data to digest for hash 1</param>
		/// <param name="input2">The data to digest for hash 2</param>
		/// <param name="input3">The data to digest for hash 3</param>
		/// <param name="input4">The data to digest for hash 4</param>
		/// <param name="outlen">The desired length of the hash</param>
		/// <returns>A 4 byte[] tuple with the calcuated hashes</returns>
		public static Tuple<byte[], byte[], byte[], byte[]> Shake256(byte[] input1, byte[] input2, byte[] input3, byte[] input4, int outlen = 136) {
			ShakeX4 shake;
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;

			shake = new ShakeX4(ShakeX4.Shake256Rate, 256, 0x1F);

			output1 = new byte[outlen];
			output2 = new byte[outlen];
			output3 = new byte[outlen];
			output4 = new byte[outlen];

			shake.Sponge(input1, input2, input3, input4, output1, output2, output3, output4, outlen);

			return new Tuple<byte[], byte[], byte[], byte[]>(output1, output2, output3, output4);
		}

#if not
		/// <summary>
		/// Calculate 4 SHA3-256 hashes in parallel.
		/// </summary>
		/// <param name="input1">The data to digest for hash 1</param>
		/// <param name="input2">The data to digest for hash 2</param>
		/// <param name="input3">The data to digest for hash 3</param>
		/// <param name="input4">The data to digest for hash 4</param>
		/// <returns>A 4 byte[] tuple with the calcuated hashes</returns>
		public static Tuple<byte[], byte[], byte[], byte[]> SHA3_224(byte[] input1, byte[] input2, byte[] input3, byte[] input4) {
			ShakeX4 shake;
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;

			shake = new ShakeX4(ShakeX4.Sha3_224Rate, 448, 0x06);

			shake.Squeeze(out output1, out output2, out output3, out output4, 224 / 8);

			return new Tuple<byte[], byte[], byte[], byte[]>(output1, output2, output3, output4);
		}

		/// <summary>
		/// Calculate 4 SHA3-256 hashes in parallel.
		/// </summary>
		/// <param name="input1">The data to digest for hash 1</param>
		/// <param name="input2">The data to digest for hash 2</param>
		/// <param name="input3">The data to digest for hash 3</param>
		/// <param name="input4">The data to digest for hash 4</param>
		/// <returns>A 4 byte[] tuple with the calcuated hashes</returns>
		public static Tuple<byte[], byte[], byte[], byte[]> SHA3_256(byte[] input1, byte[] input2, byte[] input3, byte[] input4) {
			ShakeX4 shake;
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;

			shake = new ShakeX4(ShakeX4.Sha3_256Rate, 512, 0x06);

			shake.Squeeze(out output1, out output2, out output3, out output4, 256 / 8);

			return new Tuple<byte[], byte[], byte[], byte[]>(output1, output2, output3, output4);
		}

		/// <summary>
		/// Calculate 4 SHA3-512 hashes in parallel.
		/// </summary>
		/// <param name="input1">The data to digest for hash 1</param>
		/// <param name="input2">The data to digest for hash 2</param>
		/// <param name="input3">The data to digest for hash 3</param>
		/// <param name="input4">The data to digest for hash 4</param>
		/// <returns>A 4 byte[] tuple with the calcuated hashes</returns>
		public static Tuple<byte[], byte[], byte[], byte[]> SHA3_384(byte[] input1, byte[] input2, byte[] input3, byte[] input4) {
			ShakeX4 shake;
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;

			shake = new ShakeX4(ShakeX4.Sha3_384Rate, 768, 0x06);

			shake.Squeeze(out output1, out output2, out output3, out output4, 384 / 8);

			return new Tuple<byte[], byte[], byte[], byte[]>(output1, output2, output3, output4);
		}

		/// <summary>
		/// Calculate 4 SHA3-512 hashes in parallel.
		/// </summary>
		/// <param name="input1">The data to digest for hash 1</param>
		/// <param name="input2">The data to digest for hash 2</param>
		/// <param name="input3">The data to digest for hash 3</param>
		/// <param name="input4">The data to digest for hash 4</param>
		/// <returns>A 4 byte[] tuple with the calcuated hashes</returns>
		public static Tuple<byte[], byte[], byte[], byte[]> SHA3_512(byte[] input1, byte[] input2, byte[] input3, byte[] input4) {
			ShakeX4 shake;
			byte[] output1;
			byte[] output2;
			byte[] output3;
			byte[] output4;

			shake = new ShakeX4(ShakeX4.Sha3_512Rate, 1024, 0x06);

			shake.Squeeze(out output1, out output2, out output3, out output4, 512 / 8);

			return new Tuple<byte[], byte[], byte[], byte[]>(output1, output2, output3, output4);
		}
#endif
	}
}