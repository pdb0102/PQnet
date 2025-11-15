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

using PQnet.Digest;

namespace PQnet {
	/// <summary>
	/// SHAKE256/192 implementation of ILmsHashAlgorithm
	/// RFC 9858 - SHAKE256 with 24-byte (192-bit) output
	/// </summary>
	internal class Shake256N24LmsHash : ILmsHashAlgorithm {
		public byte[] Hash(byte[] data) {
			byte[] result;

			result = Shake256.HashData(data, 24);
			return result;
		}

		public int OutputLength {
			get {
				return 24;
			}
		}

		public string Name {
			get {
				return "SHAKE256/192";
			}
		}

		public uint TypeCode {
			get {
				return 20; // LMS_SHAKE_M24_H5
			}
		}
	}
}
