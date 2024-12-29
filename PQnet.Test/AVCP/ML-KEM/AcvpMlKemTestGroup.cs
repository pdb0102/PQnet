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
	/// ML-KEM Test Group JSON Schema
	/// </summary>
	[DataContract]
	public class AcvpMlKemTestGroup<T> {
		/// <summary>
		/// Numeric identifier for the test group, unique across the entire vector set
		/// </summary>
		[DataMember(Name = "tgId")]
		public int TgId { get; set; }

		/// <summary>
		/// The test operation performed
		/// </summary>
		[DataMember(Name = "testType")]
		public string TestType { get; set; }

		/// <summary>
		/// The ML-KEM parameter set used
		/// </summary>
		[DataMember(Name = "parameterSet")]
		public string ParameterSet { get; set; }

		/// <summary>
		/// The ML-KEM operation
		/// </summary>
		[DataMember(Name = "function")]
		public string Function { get; set; }

		/// <summary>
		/// The message used to generate the signature
		/// </summary>
		[DataMember(Name = "dk")]
		public string DecapsulationKey { get; set; }

		/// <summary>
		/// <see cref="DecapsulationKey"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] DecapsulationKeyBytes {
			get {
				if (DecapsulationKey == null) {
					return null;
				}
				return Utilities.HexToBytes(DecapsulationKey, out _);
			}
		}

		/// <summary>
		/// List of individual test vector JSON objects 
		/// </summary>
		[DataMember(Name = "tests")]
		public List<T> Tests { get; set; }
	}
}