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

using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace PQnet {
	/// <summary>
	/// Cryptographically strong random number generator
	/// </summary>
	public class Rng {
		/// <summary>
		/// Generates a random byte array
		/// </summary>
		/// <param name="out_buffer">The buffer to receive the random bytes</param>
		/// <param name="outlen">The number of bytes to generate</param>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void randombytes(out byte[] out_buffer, int outlen) {
			out_buffer = RandomNumberGenerator.GetBytes(outlen);
		}
	}
}
