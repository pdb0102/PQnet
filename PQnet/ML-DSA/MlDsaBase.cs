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

// Ported from the reference implementation found at https://www.pq-crystals.org/dilithium/

using System;
using System.Security.Cryptography;

namespace PQnet {
	/// <summary>
	/// Base class for ML-DSA digital signature algorithms.
	/// </summary>
	public abstract partial class MlDsaBase : ISignature, ISecurityCategory {
		/// <summary>
		/// The size, in bytes, of the seed used for key generation
		/// </summary>
		public const int SeedBytes = 32;

		private const int CrhBytes = 64;
		private const int TrBytes = 64;
		private const int RndBytes = 32;
		private const int N = 256;
		private const int Q = 8380417;
		private const int D = 13;
		private const int PolyT1PackedBytes = 320;
		private const int PolyT0PackedBytes = 416;
		private int PolyVecHPacketBytes;
		private int PolyZPackedBytes;
		private int PolyW1PackedBytes;
		private int PolyEtaPackedBytes;

		private static readonly byte[] null_rnd = new byte[RndBytes];
		private static readonly byte[] empty_ctx = Array.Empty<byte>();

		private int K;
		private int L;
		private int Eta;
		private int Tau;
		private int Beta;
		private int Gamma1;
		private int Gamma2;
		private int Omega;
		private int CTildeBytes;

		/// <summary>
		/// Initializes a new instance of the <see cref="MlDsaBase"/> class.
		/// </summary>
		/// <param name="K"></param>
		/// <param name="L"></param>
		/// <param name="Eta"></param>
		/// <param name="Tau"></param>
		/// <param name="Beta"></param>
		/// <param name="Gamma1"></param>
		/// <param name="Gamma2"></param>
		/// <param name="Omega"></param>
		/// <param name="CTildeBytes"></param>
		/// <exception cref="NotImplementedException"></exception>
		public MlDsaBase(int K, int L, int Eta, int Tau, int Beta, int Gamma1, int Gamma2, int Omega, int CTildeBytes) {
			this.K = K;
			this.L = L;
			this.Eta = Eta;
			this.Tau = Tau;
			this.Beta = Beta;
			this.Gamma1 = Gamma1;
			this.Gamma2 = Gamma2;
			this.Omega = Omega;
			this.CTildeBytes = CTildeBytes;

			this.PolyVecHPacketBytes = Omega + K;
			if (Gamma1 == (1 << 17)) {
				PolyZPackedBytes = 576;
			} else if (Gamma1 == (1 << 19)) {
				PolyZPackedBytes = 640;
			} else {
				throw new NotImplementedException($"Unsupported Gamma1 value {Gamma1} [Allowed are '1 << 17' and '1 << 19']");
			}

			if (Gamma2 == (Q - 1) / 88) {
				PolyW1PackedBytes = 192;
			} else if (Gamma2 == (Q - 1) / 32) {
				PolyW1PackedBytes = 128;
			} else {
				throw new NotImplementedException($"Unsupported Gamma2 value {Gamma2} [Allowed are '(Q - 1) / 88' and '(Q - 1) / 32']");
			}

			if (Eta == 2) {
				PolyEtaPackedBytes = 96;
			} else if (Eta == 4) {
				PolyEtaPackedBytes = 128;
			} else {
				throw new NotImplementedException($"Unsupported Eta value {Eta} [Allowed are '2' and '4']");
			}

			PublicKeyBytes = SeedBytes + (K * PolyT1PackedBytes);
			PrivateKeyBytes = (2 * SeedBytes) + TrBytes + (L * PolyEtaPackedBytes) + (K * PolyEtaPackedBytes) + (K * PolyT0PackedBytes);
			SignatureBytes = CTildeBytes + (L * PolyZPackedBytes) + PolyVecHPacketBytes;
		}

		/// <summary>
		/// Gets whether the signature should be randomized or deterministic (predictable, same input causes same signature)
		/// </summary>
		public abstract bool Deterministic { get; }

		/// <inheritdoc/>
		public abstract int NistSecurityCategory { get; }

		/// <inheritdoc/>
		public abstract string Name { get; }

		/// <summary>
		/// Gets the size, in bytes, of the public key
		/// </summary>
		public int PublicKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the private key
		/// </summary>
		public int PrivateKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the signature
		/// </summary>
		public int SignatureBytes { get; }

		/// <summary>
		/// Generates a ML-DSA key pair. Throws if an error occurs
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <exception cref="CryptographicException"></exception>
		public void GenerateKeyPair(out byte[] public_key, out byte[] private_key) {
			if (!ml_keygen(out public_key, out private_key)) {
				throw new CryptographicException($"Key generation failed");
			}
		}

		/// <summary>
		/// Generates a ML-DSA key pair.
		/// </summary>
		/// <param name="public_key">Receives the public key</param>
		/// <param name="private_key">Receives the private key</param>
		/// <param name="error">Receives any error that occurred, or <c>null</c></param>
		/// <returns><c>true</c> if the key pair was successfully generated, <c>false</c> otherwise</returns>
		public bool GenerateKeyPair(out byte[] public_key, out byte[] private_key, out string error) {
			if (ml_keygen(out public_key, out private_key)) {
				error = null;
				return true;
			}
			error = "Key generation failed";
			return false;
		}

		/// <summary>
		/// Generates a ML-DSA key pair.
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
			if ((seed != null) && (seed.Length != SeedBytes)) {
				public_key = null;
				private_key = null;
				error = $"Seed must be {SeedBytes} bytes long";
				return false;
			}

			if (ml_keygen(out public_key, out private_key)) {
				error = null;
				return true;
			}
			error = "Key generation failed";
			return false;
		}

		/// <summary>
		/// Generate a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="signature">Receives the signature</param>
		/// <remarks>Uses an empty context string (ctx)</remarks>
		/// <exception cref="CryptographicException">Private key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		public void Sign(byte[] message, byte[] private_key, out byte[] signature) {
			if (private_key.Length != PrivateKeyBytes) {
				throw new CryptographicException($"Private key must be {PrivateKeyBytes} bytes long");
			}

			ml_sign(out signature, message, empty_ctx, private_key);
		}

		/// <summary>
		/// Generate a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">Receives the signature</param>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes, or private key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		public void Sign(byte[] message, byte[] private_key, byte[] ctx, out byte[] signature) {
			if ((ctx != null) && (ctx.Length > 255)) {
				throw new CryptographicException($"ctx must be not be longer than 255 bytes");
			}

			if (private_key.Length != PrivateKeyBytes) {
				throw new CryptographicException($"Private key must be {PrivateKeyBytes} bytes long");
			}

			ml_sign(out signature, message, ctx != null ? ctx : empty_ctx, private_key);
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
			if (private_key.Length != PrivateKeyBytes) {
				signature = null;
				error = $"Private key must be {PrivateKeyBytes} bytes long";
				return false;
			}

			if ((ctx != null) && (ctx.Length > 255)) {
				signature = null;
				error = $"ctx must be not be longer than 255 bytes";
				return false;
			}

			if (ml_sign(out signature, message, ctx != null ? ctx : empty_ctx, private_key) == 0) {
				error = null;
				return true;
			}

			signature = null;
			error = "Signature generation failed";
			return false;
		}

		/// <summary>
		/// Generate a ML-DSA signature for a digest ("pre-hash signature")
		/// </summary>
		/// <param name="digest">The message digest to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">Receives the signature</param>
		/// <remarks>Uses an empty context string (ctx)</remarks>
		/// <exception cref="CryptographicException">Private key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		public void SignHash(byte[] digest, byte[] private_key, PreHashFunction ph, out byte[] signature) {
			if (private_key.Length != PrivateKeyBytes) {
				throw new CryptographicException($"Private key must be {PrivateKeyBytes} bytes long");
			}

			signature = hash_ml_sign(private_key, digest, null, ph);
		}

		/// <summary>
		/// Generate a ML-DSA signature for a digest ("pre-hash signature")
		/// </summary>
		/// <param name="digest">The message digest to sign</param>
		/// <param name="private_key">The private key to use for signing</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">Receives the signature</param>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes, or private key length did not match the required <see cref="PrivateKeyBytes"/></exception>
		public void SignHash(byte[] digest, byte[] private_key, byte[] ctx, PreHashFunction ph, out byte[] signature) {
			if ((ctx != null) && (ctx.Length > 255)) {
				throw new CryptographicException($"ctx must be not be longer than 255 bytes");
			}

			if (private_key.Length != PrivateKeyBytes) {
				throw new CryptographicException($"Private key must be {PrivateKeyBytes} bytes long");
			}

			signature = hash_ml_sign(private_key, digest, ctx, ph);
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

			if (private_key.Length != PrivateKeyBytes) {
				signature = null;
				error = $"Private key must be {PrivateKeyBytes} bytes long";
				return false;
			}

			signature = hash_ml_sign(private_key, digest, ctx, ph);
			if (signature != null) {
				error = null;
				return true;
			}

			error = "Signature generation failed";
			return false;
		}

		/// <summary>
		/// Verify a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="signature">The message signature</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		/// <exception cref="CryptographicException">Public key length did not match the required <see cref="PublicKeyBytes"/></exception>
		public bool Verify(byte[] message, byte[] public_key, byte[] signature) {
			if (public_key.Length != PublicKeyBytes) {
				throw new CryptographicException($"Private key must be {PrivateKeyBytes} bytes long");
			}

			return ml_verify(signature, message, empty_ctx, public_key) == 0;
		}

		/// <summary>
		/// Verify a pure ML-DSA signature
		/// </summary>
		/// <param name="message">The message to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="signature">The message signature</param>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes, or the public key length did not match the required <see cref="PublicKeyBytes"/></exception>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		public bool Verify(byte[] message, byte[] public_key, byte[] ctx, byte[] signature) {
			if ((ctx != null) && (ctx.Length > 255)) {
				throw new CryptographicException($"ctx must be not be longer than 255 bytes");
			}

			if (public_key.Length != PublicKeyBytes) {
				throw new CryptographicException($"Public key must be {PublicKeyBytes} bytes long");
			}

			return ml_verify(signature, message, ctx != null ? ctx : empty_ctx, public_key) == 0;
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
				return false;
			}

			if (public_key.Length != PublicKeyBytes) {
				error = $"Public key must be {PublicKeyBytes} bytes long";
				return false;
			}

			if (ml_verify(signature, message, ctx != null ? ctx : empty_ctx, public_key) == 0) {
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
		/// <exception cref="CryptographicException">The public key length did not match the required <see cref="PublicKeyBytes"/></exception>
		public bool VerifyHash(byte[] digest, byte[] public_key, PreHashFunction ph, byte[] signature) {
			if (public_key.Length != PublicKeyBytes) {
				throw new CryptographicException($"Public key must be {PublicKeyBytes} bytes long");
			}

			return hash_ml_verify(digest, signature, null, ph, public_key);
		}

		/// <summary>
		/// Verify a digest ("pre-hash") ML-DSA signature
		/// </summary>
		/// <param name="digest">The message digest to authenticate</param>
		/// <param name="public_key">The public key to use for verification</param>
		/// <param name="ctx">The context string, or <c>null</c></param>
		/// <param name="ph">The hash function used to the create the message digest</param>
		/// <param name="signature">The message signature</param>
		/// <returns><c>true</c> if the signature is valid and the message authentic, <c>false</c> otherwise</returns>
		/// <exception cref="CryptographicException">Context was larger than 255 bytes, or the public key length did not match the required <see cref="PublicKeyBytes"/></exception>
		public bool VerifyHash(byte[] digest, byte[] public_key, byte[] ctx, PreHashFunction ph, byte[] signature) {
			if ((ctx != null) && (ctx.Length > 255)) {
				throw new CryptographicException($"ctx must be not be longer than 255 bytes");
			}

			if (public_key.Length != PublicKeyBytes) {
				throw new CryptographicException($"Public key must be {PublicKeyBytes} bytes long");
			}

			return hash_ml_verify(digest, signature, ctx, ph, public_key);
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

			if (public_key.Length != PublicKeyBytes) {
				error = $"Public key must be {PublicKeyBytes} bytes long";
				return false;
			}

			if (hash_ml_verify(digest, signature, ctx, ph, public_key)) {
				error = null;
				return true;
			}
			error = "Signature is not valid";
			return false;
		}
	}
}