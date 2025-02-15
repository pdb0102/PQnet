﻿// MIT License
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
	/// ML-DSA sigVer Test Case JSON Schema
	/// </summary>
	[DataContract]
	public class AcvpMlDsaSigVerTestCase {
		/// <summary>
		/// Numeric identifier for the test case, unique across the entire vector set
		/// </summary>
		[DataMember(Name = "tcId")]
		public int TcId { get; set; }

		/// <summary>
		/// The context used to generate the signature
		/// </summary>
		[DataMember(Name = "context")]
		public string Context { get; set; }

		/// <summary>
		/// <see cref="Context"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] ContextBytes {
			get {
				if (Context == null) {
					return null;
				}
				return Utilities.HexToBytes(Context, out _);
			}
		}

		/// <summary>
		/// The hash algorithm for Pre-Hash signatures
		/// </summary>
		[DataMember(Name = "hashAlg")]
		public string HashAlg { get; set; }

		/// <summary>
		/// The External Mu
		/// </summary>
		[DataMember(Name = "mu")]
		public string Mu { get; set; }

		/// <summary>
		/// <see cref="Mu"/> as a byte array
		/// </summary>
		[IgnoreDataMember]
		public byte[] MuBytes {
			get {
				if (Mu == null) {
					return null;
				}
				return Utilities.HexToBytes(Mu, out _);
			}
		}

		/// <summary>
		/// The message used to verify with the signature
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
		/// The signature to verify
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

		/// <summary>
		/// Gets whether the test is expected to pass
		/// </summary>
		[DataMember(Name = "testPassed")]
		public bool TestPassed { get; set; }
	}
}