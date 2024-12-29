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

namespace PQnet.test.AVCP {

	internal class Utilities {
		public static byte[] HexToBytes(string hex, out string error) {
			int length;
			int upper;
			int lower;
			int index;
			byte[] bytes;

			if ((hex == null) || (hex.Length == 0)) {
				error = null;
				return Array.Empty<byte>();
			}

			length = hex.Length;
			if ((length % 2) != 0) {
				error = "Invalid hex string; not multiple of 2";
				return null;
			}

			index = 0;
			bytes = new byte[length / 2];
			for (int l = 0; l < length; l += 2) {
				upper = hex[l];

				if (('0' <= upper) && (upper <= '9')) {
					upper -= 48;
				} else if (('A' <= upper) && (upper <= 'F')) {
					upper -= 55;
				} else if (('a' <= upper) && (upper <= 'f')) {
					upper -= 87;
				} else {
					error = $"Invalid character '{upper}' at position {l}";
					return null;
				}

				upper <<= 4;

				lower = hex[l + 1];

				if (('0' <= lower) && (lower <= '9')) {
					lower -= 48;
				} else if (('A' <= lower) && (lower <= 'F')) {
					lower -= 55;
				} else if (('a' <= lower) && (lower <= 'f')) {
					lower -= 87;
				} else {
					error = $"Invalid character '{lower}' at position {l + 1}";
					return null;
				}

				bytes[index++] = (byte)(upper + lower);
			}

			error = null;
			return bytes;
		}

	}
}