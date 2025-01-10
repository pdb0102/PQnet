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
	}
}