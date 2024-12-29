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
	public class AcvpSlhDsaSigGenTestCase {
		/// <summary>
		/// Numeric identifier for the test case, unique across the entire vector set
		/// </summary>
		[DataMember(Name = "tcId")]
		public int TcId { get; set; }

		/// <summary>
		/// The message used to generate the signature
		/// </summary>
		[DataMember(Name = "message")]
		public string Message { get; set; }

		/// <summary>
		/// <see cref="Message"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] MessageBytes {
			get {
				if (Message == null) {
					return null;
				}
				return Utilities.HexToBytes(Message, out _);
			}
		}

		/// <summary>
		/// The seed used to generate the key pair
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

		/// <summary>
		/// The random value used to generate the signature
		/// </summary>
		[DataMember(Name = "additionalRandomness")]
		public string Random { get; set; }

		/// <summary>
		/// <see cref="Random"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] RandomBytes {
			get {
				if (Random == null) {
					return null;
				}
				return Utilities.HexToBytes(Random, out _);
			}
		}

		/// <summary>
		/// The expected signature
		/// </summary>
		[DataMember(Name = "signature")]
		public string Signature { get; set; }

		/// <summary>
		/// <see cref="Random"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] SignatureBytes {
			get {
				if (Signature == null) {
					return null;
				}
				return Utilities.HexToBytes(Signature, out _);
			}
		}
	}
}