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
	/// LMS with SHAKE256/192, n=24, h=25 (33,554,432 signatures max)
	/// RFC 9858 - LMS_SHAKE_M24_H25 with LMOTS_SHAKE_N24_W8
	/// </summary>
	public class LmsShakeM24H25 : LmsBase {
		/// <summary>
		/// Initializes a new instance of the <see cref="LmsShakeM24H25"/> class
		/// </summary>
		public LmsShakeM24H25() : base(new Shake256N24LmsHash(), Lms.LMS_SHAKE_M24_H25, LmOts.LMOTS_SHAKE_N24_W8, "LMS-SHAKE-M24-H25") {
		}
	}
}
