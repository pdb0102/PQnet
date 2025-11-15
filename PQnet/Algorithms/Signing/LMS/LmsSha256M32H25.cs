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
	/// LMS with SHA-256, n=32, h=25 (33,554,432 signatures max)
	/// RFC 8554 - LMS_SHA256_M32_H25 with LMOTS_SHA256_N32_W8
	/// </summary>
	public class LmsSha256M32H25 : LmsBase {
		/// <summary>
		/// Initializes a new instance of the <see cref="LmsSha256M32H25"/> class
		/// </summary>
		public LmsSha256M32H25() : base(new Sha256LmsHash(), Lms.LMS_SHA256_M32_H25, LmOts.LMOTS_SHA256_N32_W8, "LMS-SHA256-M32-H25") {
		}
	}
}
