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
	/// SHA-256 implementation of ILmsHashAlgorithm
	/// RFC 8554 Section 5.1
	/// </summary>
	internal class Sha256LmsHash : ILmsHashAlgorithm {
		public byte[] Hash(byte[] data) {
			byte[] result;

			result = new byte[32];
			Sha256.sha256(result, data, data.Length);
			return result;
		}

		public int OutputLength {
			get {
				return 32;
			}
		}

		public string Name {
			get {
				return "SHA-256";
			}
		}

		public uint TypeCode {
			get {
				return 5; // LMS_SHA256_M32_H5
			}
		}
	}
}
