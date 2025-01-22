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

using System;
using System.Security.Cryptography;

namespace PQnet {
	/// <summary>
	/// Base class for SLH-DSA signature schemes
	/// </summary>
	public abstract partial class SlhDsaBase : ISignature {
		/// <summary>
		/// Generates a SLH-DSA key pair. Throws if an error occurs
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		public void GenerateKeyPair(out byte[] public_key, out byte[] private_key) {
			slh_keygen(out private_key, out public_key);
		}

		/// <summary>
		/// Generates a SLH-DSA key pair.
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <param name="error">Receives any error that occurred, or <c>null</c></param>
		/// <returns><c>true</c> if the key pair was successfully generated, <c>false</c> otherwise</returns>
		public bool GenerateKeyPair(out byte[] public_key, out byte[] private_key, out string error) {
			slh_keygen(out private_key, out public_key);
			error = null;
			return true;
		}

		/// <summary>
		/// Generates a SLH-DSA key pair.
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <param name="seed">Optional seed bytes for generation, or <c>null</c>.</param>
		/// <param name="error">Receives any error that occurred, or <c>null</c></param>
		/// <returns><c>true</c> if the key pair was successfully generated, <c>false</c> otherwise</returns>
		/// <remarks>
		/// If <paramref name="seed"/> is provided, it must be exactly <see cref="SeedBytes"/> bytes long.
		/// </remarks>
		public bool GenerateKeyPair(out byte[] public_key, out byte[] private_key, byte[] seed, out string error) {
			byte[] sk_seed;
			byte[] sk_prf;
			byte[] pk_seed;

			if ((seed != null) && (seed.Length != (3 * n))) {
				public_key = null;
				private_key = null;
				error = $"Seed must be {n} bytes long";
				return false;
			}

			sk_seed = new byte[n];
			sk_prf = new byte[n];
			pk_seed = new byte[n];
			Array.Copy(seed, 0, sk_prf, 0, n);
			Array.Copy(seed, n, sk_seed, 0, n);
			Array.Copy(seed, 2 * n, pk_seed, 0, n);

			(private_key, public_key) = slh_keygen_internal(sk_seed, sk_prf, pk_seed);

			error = null;
			return true;
		}

		/// <summary>
		/// Derive an SLH-DSA public key from a private key
		/// </summary>
		/// <param name="private_key">The private key</param>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="error">Receives an error that occurred, or <c>null</c></param>
		/// <returns><c>true</c> if the key was successfully returned, <c>false</c> otherwise</returns>
		public bool DerivePublicFromPrivateKey(byte[] private_key, out byte[] public_key, out string error) {
			if (private_key.Length != PrivateKeyBytes) {
				public_key = null;
				error = $"Private key must be {PrivateKeyBytes} bytes long";
				return false;
			}

			public_key = new byte[n * 2];
			Array.Copy(private_key, n * 2, public_key, 0, n * 2);
			error = null;
			return true;
		}

		/// <summary>
		/// Generate a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="signature">Receives the signature</param>
		/// <remarks>Uses an empty context string (ctx)</remarks>
		public void Sign(byte[] message, byte[] private_key, out byte[] signature) {
			signature = slh_sign(message, null, private_key);
		}

		/// <summary>
		/// Generate a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">Receives the signature</param>
		/// <exception cref="ArgumentException">Context was larger than 255 bytes</exception>
		public void Sign(byte[] message, byte[] private_key, byte[] ctx, out byte[] signature) {
			if ((ctx != null) && (ctx.Length > 255)) {
				throw new ArgumentException($"ctx must be not be longer than 255 bytes");
			}

			signature = slh_sign(message, ctx, private_key);
		}

		/// <summary>
		/// Generate a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">Receives the signature</param>
		/// <param name="error">Receives an error string on failure</param>
		/// <returns><c>true</c> if the message was successfully signed, <c>false</c> otherwise</returns>
		public bool Sign(byte[] message, byte[] private_key, byte[] ctx, out byte[] signature, out string error) {
			if ((ctx != null) && (ctx.Length > 255)) {
				signature = null;
				error = $"ctx must be not be longer than 255 bytes";
				return false;
			}

			signature = slh_sign(message, ctx, private_key);

			error = null;
			return true;
		}

		/// <summary>
		/// Generate a ML-DSA signature for a digest ("pre-hash signature")
		/// </summary>
		/// <param name="digest">The message digest to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">Receives the signature</param>
		/// <remarks>Uses an empty context string (ctx)</remarks>
		/// <exception cref="ArgumentException">The provided hash function <paramref name="ph"/> is not supported</exception>
		public void SignHash(byte[] digest, byte[] private_key, PreHashFunction ph, out byte[] signature) {
			signature = hash_slh_sign(digest, null, ph, private_key);
		}

		/// <summary>
		/// Generate a ML-DSA signature for a digest ("pre-hash signature")
		/// </summary>
		/// <param name="digest">The message digest to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">Receives the signature</param>
		/// <exception cref="ArgumentException">Context was larger than 255 bytes, or the provided hash function is not supported</exception>
		public void SignHash(byte[] digest, byte[] private_key, byte[] ctx, PreHashFunction ph, out byte[] signature) {
			if ((ctx != null) && (ctx.Length > 255)) {
				throw new CryptographicException($"ctx must be not be longer than 255 bytes");
			}

			signature = hash_slh_sign(digest, ctx, ph, private_key);
		}

		/// <summary>
		/// Generate a ML-DSA signature for a digest ("pre-hash signature")
		/// </summary>
		/// <param name="digest">The message digest to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">Receives the signature</param>
		/// <param name="error">Receives an error string on failure</param>
		/// <returns><c>true</c> if the message was successfully signed, <c>false</c> otherwise</returns>
		public bool SignHash(byte[] digest, byte[] private_key, byte[] ctx, PreHashFunction ph, out byte[] signature, out string error) {
			if ((ctx != null) && (ctx.Length > 255)) {
				signature = null;
				error = $"ctx must be not be longer than 255 bytes";
				return false;
			}

			try {
				signature = hash_slh_sign(digest, ctx, ph, private_key);
			} catch (ArgumentException e) {
				signature = null;
				error = e.Message;

				return false;
			}

			error = null;
			return true;
		}

		/// <summary>
		/// Verify a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="signature">The message signature</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		public bool Verify(byte[] message, byte[] public_key, byte[] signature) {
			return slh_verify(signature, message, null, public_key);
		}

		/// <summary>
		/// Verify a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">The message signature</param>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes</exception>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		public bool Verify(byte[] message, byte[] public_key, byte[] ctx, byte[] signature) {
			if ((ctx != null) && (ctx.Length > 255)) {
				throw new CryptographicException($"ctx must be not be longer than 255 bytes");
			}

			return slh_verify(message, signature, ctx, public_key);
		}

		/// <summary>
		/// Verify a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">The message signature</param>
		/// <param name="error">Receives an error string on failure</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		public bool Verify(byte[] message, byte[] public_key, byte[] ctx, byte[] signature, out string error) {
			if ((ctx != null) && (ctx.Length > 255)) {
				error = $"ctx must be not be longer than 255 bytes";
			}

			if (slh_verify(message, signature, ctx, public_key)) {
				error = null;
				return true;
			}
			error = "Signature is not valid";
			return false;
		}

		/// <summary>
		/// Verify a digest ("pre-hash") ML-DSA signature
		/// </summary>
		/// <param name="digest">The message digest to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">The message signature</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		public bool VerifyHash(byte[] digest, byte[] public_key, PreHashFunction ph, byte[] signature) {
			return hash_slh_verify(digest, signature, null, ph, public_key);
		}

		/// <summary>
		/// Verify a digest ("pre-hash") ML-DSA signature
		/// </summary>
		/// <param name="digest">The message digest to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">The message signature</param>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes</exception>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		public bool VerifyHash(byte[] digest, byte[] public_key, byte[] ctx, PreHashFunction ph, byte[] signature) {
			if ((ctx != null) && (ctx.Length > 255)) {
				throw new CryptographicException($"ctx must be not be longer than 255 bytes");
			}

			return hash_slh_verify(digest, signature, ctx, ph, public_key);
		}

		/// <summary>
		/// Verify a digest ("pre-hash") ML-DSA signature
		/// </summary>
		/// <param name="digest">The message digest to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">The message signature</param>
		/// <param name="error">Receives an error string on failure</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		public bool VerifyHash(byte[] digest, byte[] public_key, byte[] ctx, PreHashFunction ph, byte[] signature, out string error) {
			if ((ctx != null) && (ctx.Length > 255)) {
				error = $"ctx must be not be longer than 255 bytes";
			}

			if (hash_slh_verify(digest, signature, ctx, ph, public_key)) {
				error = null;
				return true;
			}
			error = "Signature is not valid";
			return false;
		}

	}
}
