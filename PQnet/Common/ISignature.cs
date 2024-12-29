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
	public interface ISignature {
		/// <summary>
		/// Gets the size, in bytes, of the public key
		/// </summary>
		int PublicKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the private key
		/// </summary>
		int PrivateKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the signature
		/// </summary>
		int SignatureBytes { get; }

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
		/// Generate a pure signature
		/// </summary>
		/// <param name="message">The message to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="signature">Receives the signature</param>
		/// <remarks>Uses an empty context string (ctx)</remarks>
		/// <exception cref="CryptographicException">Private key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		void Sign(byte[] message, byte[] private_key, out byte[] signature);

		/// <summary>
		/// Generate a pure signature
		/// </summary>
		/// <param name="message">The message to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">Receives the signature</param>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes, or private key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		void Sign(byte[] message, byte[] private_key, byte[] ctx, out byte[] signature);

		/// <summary>
		/// Generate a pure signature
		/// </summary>
		/// <param name="message">The message to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">Receives the signature</param>
		/// <param name="error">Receives an error string on failure</param>
		/// <returns><c>true</c> if the message was successfully signed, <c>false</c> otherwise</returns>
		bool Sign(byte[] message, byte[] private_key, byte[] ctx, out byte[] signature, out string error);

		/// <summary>
		/// Generate a signature for a digest ("pre-hash signature")
		/// </summary>
		/// <param name="digest">The message digest to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">Receives the signature</param>
		/// <remarks>Uses an empty context string (ctx)</remarks>
		/// <exception cref="CryptographicException">Private key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		void SignHash(byte[] digest, byte[] private_key, PreHashFunction ph, out byte[] signature);

		/// <summary>
		/// Generate a signature for a digest ("pre-hash signature")
		/// </summary>
		/// <param name="digest">The message digest to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">Receives the signature</param>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes, or private key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		void SignHash(byte[] digest, byte[] private_key, byte[] ctx, PreHashFunction ph, out byte[] signature);

		/// <summary>
		/// Generate a signature for a digest ("pre-hash signature")
		/// </summary>
		/// <param name="digest">The message digest to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">Receives the signature</param>
		/// <param name="error">Receives an error string on failure</param>
		/// <returns><c>true</c> if the message was successfully signed, <c>false</c> otherwise</returns>
		bool SignHash(byte[] digest, byte[] private_key, byte[] ctx, PreHashFunction ph, out byte[] signature, out string error);

		/// <summary>
		/// Verify a pure signature
		/// </summary>
		/// <param name="message">The message to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="signature">The message signature</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		/// <exception cref="CryptographicException">Public key length did not match the required <see cref="PublicKeyBytes"/></exception>
		bool Verify(byte[] message, byte[] public_key, byte[] signature);

		/// <summary>
		/// Verify a pure signature
		/// </summary>
		/// <param name="message">The message to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">The message signature</param>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes, or the public key length did not match the required <see cref="PublicKeyBytes"/></exception>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		bool Verify(byte[] message, byte[] public_key, byte[] ctx, byte[] signature);

		/// <summary>
		/// Verify a pure signature
		/// </summary>
		/// <param name="message">The message to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">The message signature</param>
		/// <param name="error">Receives an error string on failure</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		bool Verify(byte[] message, byte[] public_key, byte[] ctx, byte[] signature, out string error);

		/// <summary>
		/// Verify a digest ("pre-hash") signature
		/// </summary>
		/// <param name="digest">The message digest to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">The message signature</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		/// <exception cref="CryptographicException">The public key length did not match the required <see cref="PublicKeyBytes"/></exception>
		bool VerifyHash(byte[] digest, byte[] public_key, PreHashFunction ph, byte[] signature);

		/// <summary>
		/// Verify a digest ("pre-hash") signature
		/// </summary>
		/// <param name="digest">The message digest to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">The message signature</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes, or the public key length did not match the required <see cref="PublicKeyBytes"/></exception>
		bool VerifyHash(byte[] digest, byte[] public_key, byte[] ctx, PreHashFunction ph, byte[] signature);

		/// <summary>
		/// Verify a digest ("pre-hash") signature
		/// </summary>
		/// <param name="digest">The message digest to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">The message signature</param>
		/// <param name="error">Receives an error string on failure</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		bool VerifyHash(byte[] digest, byte[] public_key, byte[] ctx, PreHashFunction ph, byte[] signature, out string error);
	}
}
