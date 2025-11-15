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

namespace PQnet {
	/// <summary>
	/// LMS with SHA-256/192, n=24, h=15 (32,768 signatures max)
	/// RFC 9858 - LMS_SHA256_M24_H15 with LMOTS_SHA256_N24_W8
	/// </summary>
	public class LmsSha256M24H15 : LmsBase {
		/// <summary>
		/// Initializes a new instance of the <see cref="LmsSha256M24H15"/> class
		/// </summary>
		public LmsSha256M24H15() : base(new Sha256N24LmsHash(), Lms.LMS_SHA256_M24_H15, LmOts.LMOTS_SHA256_N24_W8, "LMS-SHA256-M24-H15") {
		}
	}
}
