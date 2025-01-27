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

using System.Security.Cryptography;

namespace PQnet {
	/// <summary>
	/// Base class for ML-KEM key encapsulation algorithms.
	/// </summary>
	public abstract partial class MlKemBase : IEncapsulate {

		/// <summary>
		/// Generates a ML-KEM key pair. Throws if an error occurs
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <exception cref="CryptographicException"></exception>
		public void GenerateKeyPair(out byte[] public_key, out byte[] private_key) {
			if (crypto_kem_keypair(out public_key, out private_key) != 0) {
				throw new CryptographicException($"Key generation failed");
			}
		}

		/// <summary>
		/// Generates a ML-KEM key pair.
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <param name="error">Receives any error that occurred, or <c>null</c></param>
		/// <returns><c>true</c> if the key pair was successfully generated, <c>false</c> otherwise</returns>
		public bool GenerateKeyPair(out byte[] public_key, out byte[] private_key, out string error) {
			if (crypto_kem_keypair(out public_key, out private_key) == 0) {
				error = null;
				return true;
			}
			error = "Key generation failed";
			return false;
		}

		/// <summary>
		/// Generates a ML-KEM key pair.
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <param name="seed">Optional seed ('d' || 'z') bytes for generation, or <c>null</c>.</param>
		/// <param name="error">Receives any error that occurred, or <c>null</c></param>
		/// <returns><c>true</c> if the key pair was successfully generated, <c>false</c> otherwise</returns>
		/// <remarks>
		/// If a seed is provided, it must be of 2 *<see cref="SeedBytes"/> bytes length.
		/// </remarks>
		public bool GenerateKeyPair(out byte[] public_key, out byte[] private_key, byte[] seed, out string error) {
			if ((seed != null) && (seed.Length != (2 * SeedBytes))) {
				public_key = null;
				private_key = null;
				error = $"{nameof(seed)} must be 2 * {SeedBytes} bytes long";
				return false;
			}
			if (seed == null) {
				if (crypto_kem_keypair(out public_key, out private_key) == 0) {
					error = null;
					return true;
				}
			} else {
				if (crypto_kem_keypair_derand(out public_key, out private_key, seed) == 0) {
					error = null;
					return true;
				}
			}
			error = "Key generation failed";
			return false;
		}

		/// <summary>
		/// Use the public (encapsulation) key to generate a shared secret key and an associated ciphertext.
		/// </summary>
		/// <param name="public_key">The public (encapsulation) key to use</param>
		/// <param name="shared_secret_key">Receives the shared secret key</param>
		/// <param name="ciphertext">Receives the ciphertet</param>
		/// <exception cref="CryptographicException">The public (encapsulation) key length did not match the required <see cref="PublicKeyBytes"/></exception>
		public void Encapsulate(byte[] public_key, out byte[] shared_secret_key, out byte[] ciphertext) {
			if (public_key.Length != PublicKeyBytes) {
				throw new CryptographicException($"Public (encapsulation) key must be {PublicKeyBytes} bytes long");
			}
			crypto_kem_enc(out ciphertext, out shared_secret_key, public_key);
		}

		/// <summary>
		/// Use the public (encapsulation) key to generate a shared secret key and an associated ciphertext.
		/// </summary>
		/// <param name="public_key">The public (encapsulation) key to use</param>
		/// <param name="shared_secret_key">Receives the shared secret key</param>
		/// <param name="ciphertext">Receives the ciphertet</param>
		/// <param name="error">Receives an error description, or <c>null</c></param>
		/// <returns><c>true</c> on success, <c>false</c> otherwise</returns>
		public bool Encapsulate(byte[] public_key, out byte[] shared_secret_key, out byte[] ciphertext, out string error) {
			if (public_key.Length != PublicKeyBytes) {
				shared_secret_key = null;
				ciphertext = null;
				error = $"Public (encapsulation) key must be {PublicKeyBytes} bytes long";
				return false;
			}

			crypto_kem_enc(out ciphertext, out shared_secret_key, public_key);

			error = null;
			return true;
		}

		/// <summary>
		/// Use the private (decapsulation) key to produce a shared secret key from a ciphertext
		/// </summary>
		/// <param name="private_key">The private (decapsulation) key to use</param>
		/// <param name="ciphertext">The ciphertext</param>
		/// <param name="shared_secret_key">Receives the shared_secret key</param>
		/// <exception cref="CryptographicException">The private (decapsulation) key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		public void Decapsulate(byte[] private_key, byte[] ciphertext, out byte[] shared_secret_key) {
			if (private_key.Length != PrivateKeyBytes) {
				throw new CryptographicException($"Private (decapsulation) key must be {PrivateKeyBytes} long");
			}
			crypto_kem_dec(out shared_secret_key, ciphertext, private_key);
		}

		/// <summary>
		/// Use the private (decapsulation) key to produce a shared secret key from a ciphertext
		/// </summary>
		/// <param name="private_key">The private (decapsulation) key to use</param>
		/// <param name="ciphertext">The ciphertext</param>
		/// <param name="shared_secret_key">Receives the shared_secret key</param>
		/// <param name="error">Receives an error description, or <c>null</c></param>
		/// <returns><c>true</c> on success, <c>false</c> otherwise</returns>
		public bool Decapsulate(byte[] private_key, byte[] ciphertext, out byte[] shared_secret_key, out string error) {
			if (private_key.Length != PrivateKeyBytes) {
				shared_secret_key = null;
				error = $"Private (decapsulation) key must be {PrivateKeyBytes} long";
				return false;
			}

			crypto_kem_dec(out shared_secret_key, ciphertext, private_key);

			error = null;
			return true;
		}
	}
}
