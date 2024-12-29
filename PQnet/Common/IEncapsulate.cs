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
	/// Interface for signature algorithms
	/// </summary>
	public interface IEncapsulate {
		/// <summary>
		/// Gets the size, in bytes, of the public key
		/// </summary>
		int PublicKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the private key
		/// </summary>
		int PrivateKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the ciphertext
		/// </summary>
		int CiphertextBytes { get; }

		/// <summary>
		/// Gets name of the algorithm
		/// </summary>
		string Name { get; }

		/// <summary>
		/// Generates a pair. Throws if an error occurs
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <exception cref="CryptographicException"></exception>
		void GenerateKeyPair(out byte[] public_key, out byte[] private_key);

		/// <summary>
		/// Generates a key pair.
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <param name="error">Receives any error that occurred, or <c>null</c></param>
		/// <returns><c>true</c> if the key pair was successfully generated, <c>false</c> otherwise</returns>
		bool GenerateKeyPair(out byte[] public_key, out byte[] private_key, out string error);

		/// <summary>
		/// Generates a key pair.
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <param name="seed">Optional seed bytes for generation, or <c>null</c>.</param>
		/// <param name="error">Receives any error that occurred, or <c>null</c></param>
		/// <returns><c>true</c> if the key pair was successfully generated, <c>false</c> otherwise</returns>
		bool GenerateKeyPair(out byte[] public_key, out byte[] private_key, byte[] seed, out string error);

		/// <summary>
		/// Use the public (encapsulation) key to generate a shared secret key and an associated ciphertext.
		/// </summary>
		/// <param name="public_key">The public (encapsulation) key to use</param>
		/// <param name="shared_secret_key">Receives the shared secret key</param>
		/// <param name="ciphertext">Receives the ciphertet</param>
		/// <exception cref="CryptographicException">The public (encapsulation) key length did not match the required <see cref="PublicKeyBytes"/></exception>
		void Encapsulate(byte[] public_key, out byte[] shared_secret_key, out byte[] ciphertext);

		/// <summary>
		/// Use the public (encapsulation) key to generate a shared secret key and an associated ciphertext.
		/// </summary>
		/// <param name="public_key">The public (encapsulation) key to use</param>
		/// <param name="shared_secret_key">Receives the shared secret key</param>
		/// <param name="ciphertext">Receives the ciphertet</param>
		/// <param name="error">Receives an error description, or <c>null</c></param>
		/// <returns><c>true</c> on success, <c>false</c> otherwise</returns>
		bool Encapsulate(byte[] public_key, out byte[] shared_secret_key, out byte[] ciphertext, out string error);

		/// <summary>
		/// Use the private (decapsulation) key to produce a shared secret key from a ciphertext
		/// </summary>
		/// <param name="private_key">The private (decapsulation) key to use</param>
		/// <param name="ciphertext">The ciphertext</param>
		/// <param name="shared_secret_key">Receives the shared_secret key</param>
		/// <exception cref="CryptographicException">The private (decapsulation) key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		void Decapsulate(byte[] private_key, byte[] ciphertext, out byte[] shared_secret_key);

		/// <summary>
		/// Use the private (decapsulation) key to produce a shared secret key from a ciphertext
		/// </summary>
		/// <param name="private_key">The private (decapsulation) key to use</param>
		/// <param name="ciphertext">The ciphertext</param>
		/// <param name="shared_secret_key">Receives the shared_secret key</param>
		/// <param name="error">Receives an error description, or <c>null</c></param>
		/// <returns><c>true</c> on success, <c>false</c> otherwise</returns>
		bool Decapsulate(byte[] private_key, byte[] ciphertext, out byte[] shared_secret_key, out string error);
	}
}
