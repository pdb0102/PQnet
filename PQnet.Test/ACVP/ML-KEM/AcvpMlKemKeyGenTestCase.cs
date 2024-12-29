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
	/// ML-KEM keyGen Test Case JSON Schema
	/// </summary>
	[DataContract]
	public class AcvpMlKemKeyGenTestCase {
		/// <summary>
		/// Numeric identifier for the test case, unique across the entire vector set
		/// </summary>
		[DataMember(Name = "tcId")]
		public int TcId { get; set; }

		/// <summary>
		/// Randomness z used to generate the key pair
		/// </summary>
		[DataMember(Name = "z")]
		public string Z { get; set; }

		/// <summary>
		/// <see cref="Z"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] ZBytes {
			get {
				if (Z == null) {
					return null;
				}
				return Utilities.HexToBytes(Z, out _);
			}
		}

		/// <summary>
		/// Randomness d used to generate the key pair
		/// </summary>
		[DataMember(Name = "d")]
		public string D { get; set; }

		/// <summary>
		/// <see cref="D"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] DBytes {
			get {
				if (D == null) {
					return null;
				}
				return Utilities.HexToBytes(D, out _);
			}
		}

		/// <summary>
		/// The public key
		/// </summary>
		[DataMember(Name = "ek")]
		public string EncapsulationKey { get; set; }

		/// <summary>
		/// <see cref="EncapsulationKey"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] EncapsulationKeyBytes {
			get {
				if (EncapsulationKey == null) {
					return null;
				}
				return Utilities.HexToBytes(EncapsulationKey, out _);
			}
		}

		/// <summary>								   
		/// The public key
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
	}
}