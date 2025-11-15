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
	/// SHA-256/192 (truncated) implementation of ILmsHashAlgorithm
	/// RFC 9858 - Uses first 24 bytes of SHA-256 output
	/// </summary>
	internal class Sha256N24LmsHash : ILmsHashAlgorithm {
		public byte[] Hash(byte[] data) {
			byte[] full_hash;
			byte[] result;

			full_hash = new byte[32];
			result = new byte[24];

			Sha256.sha256(full_hash, data, data.Length);
			System.Array.Copy(full_hash, 0, result, 0, 24);

			return result;
		}

		public int OutputLength {
			get {
				return 24;
			}
		}

		public string Name {
			get {
				return "SHA-256/192";
			}
		}

		public uint TypeCode {
			get {
				return 10; // LMS_SHA256_M24_H5
			}
		}
	}
}
