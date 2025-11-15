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
	/// LMS keyGen Test Case JSON Schema
	/// </summary>
	[DataContract]
	public class AcvpLmsKeyGenTestCase {
		/// <summary>
		/// Numeric identifier for the test case, unique across the entire vector set
		/// </summary>
		[DataMember(Name = "tcId")]
		public int TcId { get; set; }

		/// <summary>
		/// The seed used to generate the key pair
		/// </summary>
		[DataMember(Name = "seed")]
		public string Seed { get; set; }

		/// <summary>
		/// <see cref="Seed"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] SeedBytes {
			get {
				if (Seed == null) {
					return null;
				}
				return Utilities.HexToBytes(Seed, out _);
			}
		}

		/// <summary>
		/// The I value (16-byte identifier)
		/// </summary>
		[DataMember(Name = "i")]
		public string I { get; set; }

		/// <summary>
		/// <see cref="I"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] IBytes {
			get {
				if (I == null) {
					return null;
				}
				return Utilities.HexToBytes(I, out _);
			}
		}

		/// <summary>
		/// The public key
		/// </summary>
		[DataMember(Name = "publicKey")]
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
		/// The private key
		/// </summary>
		[DataMember(Name = "privateKey")]
		public string PrivateKey { get; set; }

		/// <summary>
		/// <see cref="PrivateKey"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] PrivateKeyBytes {
			get {
				if (PrivateKey == null) {
					return null;
				}
				return Utilities.HexToBytes(PrivateKey, out _);
			}
		}
	}
}
