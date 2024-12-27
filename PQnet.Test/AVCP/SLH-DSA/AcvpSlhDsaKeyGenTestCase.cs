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
	/// SLH-DSA sigGen Test Case JSON Schema
	/// </summary>
	[DataContract]
	public class AcvpSlhDsaKeyGenTestCase {
		/// <summary>
		/// Numeric identifier for the test case, unique across the entire vector set
		/// </summary>
		[DataMember(Name = "tcId")]
		public int TcId { get; set; }

		/// <summary>
		/// The secret key seed used to generate the key pair
		/// </summary>
		[DataMember(Name = "skSeed")]
		public string SkSeed { get; set; }

		/// <summary>
		/// <see cref="SkSeed"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] SkSeedBytes {
			get {
				if (SkSeed == null) {
					return null;
				}
				return Utilities.HexToBytes(SkSeed, out _);
			}
		}

		/// <summary>
		/// The secret key PRF used to generate the key pair
		/// </summary>
		[DataMember(Name = "skPrf")]
		public string SkPrf { get; set; }

		/// <summary>
		/// <see cref="SkPrf"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] SkPrfBytes {
			get {
				if (SkPrf == null) {
					return null;
				}
				return Utilities.HexToBytes(SkPrf, out _);
			}
		}

		/// <summary>
		/// The public key seed used to generate the key pair
		/// </summary>
		[DataMember(Name = "pkSeed")]
		public string PkSeed { get; set; }

		/// <summary>
		/// <see cref="PkSeed"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] PkSeedBytes {
			get {
				if (PkSeed == null) {
					return null;
				}
				return Utilities.HexToBytes(PkSeed, out _);
			}
		}

		/// <summary>
		/// The public key
		/// </summary>
		[DataMember(Name = "pk")]
		public string PublicKey { get; set; }

		/// <summary>
		/// <see cref="PublicKey"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] PublicKeyBytes {
			get {
				if (PublicKey == null) {
					return null;
				}
				return Utilities.HexToBytes(PublicKey, out _);
			}
		}

		/// <summary>								   
		/// The public key
		/// </summary>
		[DataMember(Name = "sk")]
		public string SecretKey { get; set; }

		/// <summary>
		/// <see cref="SecretKey"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] SecretKeyBytes {
			get {
				if (SecretKey == null) {
					return null;
				}
				return Utilities.HexToBytes(SecretKey, out _);
			}
		}

	}
}