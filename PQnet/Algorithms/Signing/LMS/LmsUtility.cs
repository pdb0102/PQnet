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

using System;

namespace PQnet {
	/// <summary>
	/// RFC 8554 - Utility functions for LMS
	/// </summary>
	internal static class LmsUtility {
		/// <summary>
		/// Converts a 16-bit unsigned integer to a 2-byte array (big-endian)
		/// </summary>
		/// <param name="x">The value to convert</param>
		/// <param name="s">The destination array</param>
		/// <param name="offset">The offset in the destination array</param>
		public static void u16str(ushort x, byte[] s, int offset) {
			s[offset] = (byte)((x >> 8) & 0xff);
			s[offset + 1] = (byte)(x & 0xff);
		}

		/// <summary>
		/// Converts a 32-bit unsigned integer to a 4-byte array (big-endian)
		/// </summary>
		/// <param name="x">The value to convert</param>
		/// <param name="s">The destination array</param>
		/// <param name="offset">The offset in the destination array</param>
		public static void u32str(uint x, byte[] s, int offset) {
			s[offset] = (byte)((x >> 24) & 0xff);
			s[offset + 1] = (byte)((x >> 16) & 0xff);
			s[offset + 2] = (byte)((x >> 8) & 0xff);
			s[offset + 3] = (byte)(x & 0xff);
		}

		/// <summary>
		/// Converts a 2-byte array (big-endian) to a 16-bit unsigned integer
		/// </summary>
		/// <param name="s">The source array</param>
		/// <param name="offset">The offset in the source array</param>
		/// <returns>The converted value</returns>
		public static ushort strTou16(byte[] s, int offset) {
			ushort result;

			result = (ushort)((s[offset] << 8) | s[offset + 1]);
			return result;
		}

		/// <summary>
		/// Converts a 4-byte array (big-endian) to a 32-bit unsigned integer
		/// </summary>
		/// <param name="s">The source array</param>
		/// <param name="offset">The offset in the source array</param>
		/// <returns>The converted value</returns>
		public static uint strTou32(byte[] s, int offset) {
			uint result;

			result = ((uint)s[offset] << 24) | ((uint)s[offset + 1] << 16) | ((uint)s[offset + 2] << 8) | s[offset + 3];
			return result;
		}

		/// <summary>
		/// Computes the checksum for LM-OTS as defined in RFC 8554 Algorithm 2
		/// </summary>
		/// <param name="s">The message hash</param>
		/// <param name="w">The Winternitz parameter (must be 1, 2, 4, or 8)</param>
		/// <param name="n">The length of hash outputs in bytes</param>
		/// <returns>The checksum value</returns>
		public static uint checksum(byte[] s, int w, int n) {
			uint sum;
			int max;

			sum = 0;
			max = (1 << w) - 1;

			for (int i = 0; i < (n * 8 / w); i++) {
				sum = sum + (uint)(max - coef(s, i, w));
			}

			return sum << (w - (((n * 8) % w)));
		}

		/// <summary>
		/// Extracts the i-th w-bit coefficient from byte string S
		/// RFC 8554 Algorithm 1
		/// </summary>
		/// <param name="s">The byte string</param>
		/// <param name="i">The coefficient index</param>
		/// <param name="w">The Winternitz parameter</param>
		/// <returns>The extracted coefficient</returns>
		public static byte coef(byte[] s, int i, int w) {
			byte result;

			result = (byte)((s[(i * w) / 8] >> (8 - ((i * w) % 8) - w)) & ((1 << w) - 1));
			return result;
		}
	}
}
