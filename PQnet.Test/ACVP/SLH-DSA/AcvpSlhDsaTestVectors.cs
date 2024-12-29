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

using System.Runtime.Serialization;

namespace PQnet.test.AVCP {
	/// <summary>
	/// SLH-DSA keyGen/sigGen/sigVer Test Case JSON Schema
	/// </summary>
	[DataContract]
	public class AcvpSlhDsaTestVectors<T> {
		/// <summary>
		/// Unique numeric vector set identifier
		/// </summary>
		[DataMember(Name = "vsId")]
		public int VsId { get; set; }

		/// <summary>
		/// Algorithm defined in the capability exchange
		/// </summary>
		[DataMember(Name = "algorithm")]
		public string Algorithm { get; set; }

		/// <summary>
		/// Mode defined in the capability exchange
		/// </summary>
		[DataMember(Name = "mode")]
		public string Mode { get; set; }

		/// <summary>
		/// Protocol test revision selected
		/// </summary>
		[DataMember(Name = "revision")]
		public string Revision { get; set; }

		/// <summary>
		/// 
		/// </summary>
		[DataMember(Name = "isSample")]
		public bool IsSample { get; set; }

		/// <summary>
		/// List of test groups
		/// </summary>
		[DataMember(Name = "testGroups")]
		public List<AcvpSlhDsaTestGroup<T>> TestGroups { get; set; }
	}
}