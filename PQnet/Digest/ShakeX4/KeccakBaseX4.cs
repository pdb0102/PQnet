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

using System.Runtime.Intrinsics.Arm;
using System.Runtime.Intrinsics.X86;

namespace PQnet.Digest {
	/// <summary>
	/// A SIMD-optimized implementation of the Keccak algorithm that calculates 4 hashes in parallel.
	/// </summary>
	public partial class KeccakBaseX4 {
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
		/// Indicates if the SIMD-optimized SHAKE128, SHAKE256, SHA3-256, and SHA3-512 are supported.
		/// </summary>
		public static bool IsSupported {
			get {
				return Avx2.IsSupported || ArmBase.IsSupported; // Being an optimist and assuming I'll get to ARM as well?
			}
		}

#if addme
		/// <summary>
		/// Absorb data into the Keccak state
		/// </summary>
		/// <param name="in_buf">The data to absorb</param>
		/// <param name="inlen">The number of bytes to absorb from <paramref name="inlen"/></param>
		/// <returns>The new position in the current block</returns>
		/// <remarks>Updates the position in the current block</remarks>
		public virtual int Absorb(byte[] in_buf1, byte[] in_buf2, byte[] in_buf3, byte[] in_buf4, int inlen) {
		}

		/// <summary>
		/// Finalizes the absorb step
		/// </summary>
		/// <remarks>This method absorbs the prefix (domain separation byte) and end-marker into the state. Updates the position to the end of the current block.</remarks>
		public virtual void FinalizeAbsorb() {

		}

		/// <summary>
		/// Squeeze data from the Keccak state
		/// </summary>
		/// <param name="out_buf">The buffer to store squeeded bytes</param>
		/// <param name="out_buf_pos">The index into <paramref name="out_buf"/> where to start storing squeezed bytes</param>
		/// <param name="outlen">The number of bytes to squeeze out</param>
		/// <returns>The new position in current block</returns>
		public virtual int Squeeze(byte[] out_buf, int out_buf_pos, int outlen) {
		}

		/// <summary>
		/// Absorb data into the Keccak state and finalize the absorb step
		/// </summary>
		/// <param name="in_buf">The data to absorb</param>
		/// <param name="inlen">The number of bytes to absorb from <paramref name="in_buf"/></param>
		/// <remarks>Updates the position in the current block to the end of the block</remarks>
		public virtual void AbsorbOnce(byte[] in_buf, int inlen) {

		}

		/// <summary>
		/// Squeeze full blocks of <see cref="rate"/> bytes each
		/// </summary>
		/// <param name="out_buf">The buffer to store squeeded bytes</param>
		/// <param name="out_buf_pos">The index into <paramref name="out_buf"/> where to start storing squeezed bytes</param>
		/// <param name="nblocks"></param>
		/// <returns>Number of bytes stored in <paramref name="out_buf"/></returns>
		/// <remarks>Starts squeezing at the beginning of the current block (assumes nothing has been squeezed from the current block yet). Can be called multiple times.</remarks>
		public virtual int SqueezeBlocks(byte[] out_buf, int out_buf_pos, int nblocks) {

		}

		/// <summary>
		/// One-shot compute of the hash of the input data
		/// </summary>
		/// <param name="out_buf">The buffer receiving the hash</param>
		/// <param name="outlen">The desired length of the hash</param>
		/// <param name="input">The data for which to compute the hash</param>
		/// <param name="inlen">The number of bytes to consume from <paramref name="input"/></param>
		/// <returns>The SHAKE hash for <paramref name="input"/></returns>
		/// <remarks>Resets any existing state on input</remarks>
		public virtual void Hash(byte[] out_buf, int outlen, byte[] input, int inlen) {

		}

#endif
	}
}