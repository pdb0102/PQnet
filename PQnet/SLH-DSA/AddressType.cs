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

namespace PQnet.SLH_DSA {
	/// <summary>
	/// FIPS 205 Section 4.2 - Enumeration of the different types of addresses used in the SLH-DSA algorithm.
	/// </summary>
	public enum AddressType : byte {
		/// <summary>
		///  WOTS+ hash address
		/// </summary>
		WotsHash = 0,

		/// <summary>
		/// WOTS+ public key address
		/// </summary>
		WotsPk = 1,

		/// <summary>
		/// Hash tree address
		/// </summary>
		Tree = 2,

		/// <summary>
		/// FORS tree address
		/// </summary>
		ForsTree = 3,

		/// <summary>
		/// FOTS tree roots compression address
		/// </summary>
		ForsRoots = 4,

		/// <summary>
		/// WOTS+ key generation address
		/// </summary>
		WotsPrf = 5,

		/// <summary>
		/// FORS key generation address
		/// </summary>
		ForsPrf = 6
	}
}