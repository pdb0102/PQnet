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
	/// ML-KEM encapDecap Test Case JSON Schema
	/// </summary>
	[DataContract]
	public class AcvpMlKemEncapDecapTestCase {
		/// <summary>
		/// Numeric identifier for the test case, unique across the entire vector set
		/// </summary>
		[DataMember(Name = "tcId")]
		public int TcId { get; set; }

		/// <summary>
		/// The message to encrypt
		/// </summary>
		[DataMember(Name = "m")]
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
		/// The encapsulation key
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
		/// The encrypted message
		/// </summary>
		[DataMember(Name = "c")]
		public string EncryptedMessage { get; set; }

		/// <summary>
		/// <see cref="EncryptedMessage"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] EncryptedMessageBytes {
			get {
				if (EncryptedMessage == null) {
					return null;
				}
				return Utilities.HexToBytes(EncryptedMessage, out _);
			}
		}
	}
}