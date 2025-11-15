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

using System;

namespace PQnet {
	/// <summary>
	/// Base class for LMS (Leighton-Micali Signature) implementations
	/// RFC 8554
	/// </summary>
	public abstract class LmsBase {
		private ILmsHashAlgorithm hash;
		private uint lms_typecode;
		private uint ots_typecode;
		private int h;
		private int n;
		private int w;
		private int p;
		private string name;

		/// <summary>
		/// Initializes a new instance of the <see cref="LmsBase"/> class
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="lms_typecode">The LMS type code</param>
		/// <param name="ots_typecode">The LM-OTS type code</param>
		/// <param name="name">The name of this LMS variant</param>
		protected LmsBase(ILmsHashAlgorithm hash, uint lms_typecode, uint ots_typecode, string name) {
			this.hash = hash;
			this.lms_typecode = lms_typecode;
			this.ots_typecode = ots_typecode;
			this.name = name;

			h = Lms.GetTreeHeight(lms_typecode);
			n = hash.OutputLength;
			w = LmOts.GetWinternitzParameter(ots_typecode);
			p = LmOts.CalculateP(n, w);

			PublicKeyBytes = 4 + 4 + 16 + n;
			PrivateKeyBytes = 4 + 4 + 16 + n + 4;
			SignatureBytes = 4 + 4 + n + (p * n) + 4 + (h * n);
		}

		/// <summary>
		/// Gets the name of this LMS variant
		/// </summary>
		public string Name {
			get {
				return name;
			}
		}

		/// <summary>
		/// Gets the size of the public key in bytes
		/// </summary>
		public int PublicKeyBytes { get; private set; }

		/// <summary>
		/// Gets the size of the private key in bytes
		/// </summary>
		public int PrivateKeyBytes { get; private set; }

		/// <summary>
		/// Gets the size of the signature in bytes
		/// </summary>
		public int SignatureBytes { get; private set; }

		/// <summary>
		/// Gets the tree height
		/// </summary>
		public int TreeHeight {
			get {
				return h;
			}
		}

		/// <summary>
		/// Gets the maximum number of signatures that can be generated with one key pair
		/// </summary>
		public int MaxSignatures {
			get {
				return 1 << h;
			}
		}

		/// <summary>
		/// Generates a new LMS key pair
		/// </summary>
		/// <param name="public_key">The generated public key</param>
		/// <param name="private_key">The generated private key</param>
		public void GenerateKeyPair(out byte[] public_key, out byte[] private_key) {
			byte[] I;
			byte[] SEED;

			// Generate random identifier
			I = new byte[16];
			Rng.randombytes(out I, 16);

			// Generate random seed
			SEED = new byte[n];
			Rng.randombytes(out SEED, n);

			Lms.GenerateKeyPair(hash, lms_typecode, ots_typecode, I, SEED, out public_key, out private_key);
		}

		/// <summary>
		/// Generates a new LMS key pair with specified identifier and seed
		/// </summary>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="SEED">The master seed</param>
		/// <param name="public_key">The generated public key</param>
		/// <param name="private_key">The generated private key</param>
		public void GenerateKeyPair(byte[] I, byte[] SEED, out byte[] public_key, out byte[] private_key) {
			if (I.Length != 16) {
				throw new ArgumentException("Identifier must be exactly 16 bytes");
			}

			if (SEED.Length != n) {
				throw new ArgumentException($"SEED must be exactly {n} bytes");
			}

			Lms.GenerateKeyPair(hash, lms_typecode, ots_typecode, I, SEED, out public_key, out private_key);
		}

		/// <summary>
		/// Signs a message using LMS
		/// </summary>
		/// <param name="private_key">The LMS private key</param>
		/// <param name="message">The message to sign</param>
		/// <param name="updated_private_key">The updated private key (with incremented signature count)</param>
		/// <returns>The LMS signature</returns>
		public byte[] Sign(byte[] private_key, byte[] message, out byte[] updated_private_key) {
			byte[] signature;

			signature = Lms.Sign(hash, private_key, message, out updated_private_key);
			return signature;
		}

		/// <summary>
		/// Verifies an LMS signature
		/// </summary>
		/// <param name="public_key">The LMS public key</param>
		/// <param name="signature">The LMS signature</param>
		/// <param name="message">The message that was signed</param>
		/// <returns>True if the signature is valid, false otherwise</returns>
		public bool Verify(byte[] public_key, byte[] signature, byte[] message) {
			bool result;

			result = Lms.Verify(hash, public_key, signature, message);
			return result;
		}

		/// <summary>
		/// Gets the number of signatures that have been used from this private key
		/// </summary>
		/// <param name="private_key">The LMS private key</param>
		/// <returns>The number of signatures used</returns>
		public uint GetSignatureCount(byte[] private_key) {
			uint q;

			q = LmsUtility.strTou32(private_key, 24 + n);
			return q;
		}

		/// <summary>
		/// Checks if the private key has been exhausted (all signatures used)
		/// </summary>
		/// <param name="private_key">The LMS private key</param>
		/// <returns>True if exhausted, false otherwise</returns>
		public bool IsExhausted(byte[] private_key) {
			uint q;

			q = GetSignatureCount(private_key);
			return q >= MaxSignatures;
		}
	}
}
