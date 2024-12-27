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

namespace PQnet.SLH_DSA {
	/// <summary>
	/// FIPS 205 Section 4.4 Arrays, Byte Strings, and Integers
	/// </summary>
	internal static class Utility {
		/// <summary>
		/// FIPS 205 Algorithm 2 - Load a <see cref="uint"/> from a <see cref="byte"/> array in big-endian order at offset <paramref name="offset"/>.
		/// </summary>
		/// <param name="b"></param>
		/// <param name="offset"></param>
		/// <returns></returns>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static uint toInt(byte[] b, int offset) {
			return (uint)((b[offset + 0] << 24) | (b[offset + 1] << 16) | (b[offset + 2] << 8) | b[offset + 3]);
		}

		/// <summary>
		/// FIPS 205 Algorithm 3 - Store a <see cref="uint"/> in a <see cref="byte"/> array in big-endian order at offset <paramref name="offset"/>.
		/// </summary>
		/// <param name="b"></param>
		/// <param name="offset"></param>
		/// <param name="i"></param>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void toByte(uint i, byte[] b, int offset) {
			b[offset + 0] = (byte)(i >> 24);
			b[offset + 1] = (byte)(i >> 16);
			b[offset + 2] = (byte)(i >> 8);
			b[offset + 3] = (byte)i;
		}

		/// <summary>
		/// FIPS 205 Algorithm 3 - Store a <see cref="ulong"/> in a <see cref="byte"/> array in big-endian order at offset <paramref name="offset"/>.
		/// </summary>
		/// <param name="b"></param>
		/// <param name="offset"></param>
		/// <param name="i"></param>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		public static void toByte(ulong i, byte[] b, int offset) {
			b[offset + 0] = (byte)(i >> 56);
			b[offset + 1] = (byte)(i >> 48);
			b[offset + 2] = (byte)(i >> 40);
			b[offset + 3] = (byte)(i >> 32);
			b[offset + 4] = (byte)(i >> 24);
			b[offset + 5] = (byte)(i >> 16);
			b[offset + 6] = (byte)(i >> 8);
			b[offset + 7] = (byte)i;
		}
	}
}