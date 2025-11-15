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
	/// RFC 8554 - LM-OTS (Leighton-Micali One-Time Signature) implementation
	/// </summary>
	internal static class LmOts {
		// LM-OTS type constants (RFC 8554 Section 4.1)
		public const uint LMOTS_SHA256_N32_W1 = 1;
		public const uint LMOTS_SHA256_N32_W2 = 2;
		public const uint LMOTS_SHA256_N32_W4 = 3;
		public const uint LMOTS_SHA256_N32_W8 = 4;

		// LM-OTS type constants (RFC 9858 - SHA-256/192)
		public const uint LMOTS_SHA256_N24_W1 = 5;
		public const uint LMOTS_SHA256_N24_W2 = 6;
		public const uint LMOTS_SHA256_N24_W4 = 7;
		public const uint LMOTS_SHA256_N24_W8 = 8;

		// LM-OTS type constants (RFC 9858 - SHAKE256/256)
		public const uint LMOTS_SHAKE_N32_W1 = 9;
		public const uint LMOTS_SHAKE_N32_W2 = 10;
		public const uint LMOTS_SHAKE_N32_W4 = 11;
		public const uint LMOTS_SHAKE_N32_W8 = 12;

		// LM-OTS type constants (RFC 9858 - SHAKE256/192)
		public const uint LMOTS_SHAKE_N24_W1 = 13;
		public const uint LMOTS_SHAKE_N24_W2 = 14;
		public const uint LMOTS_SHAKE_N24_W4 = 15;
		public const uint LMOTS_SHAKE_N24_W8 = 16;

		// D_PBLC constant for hash function domain separation
		private const ushort D_PBLC = 0x8080;

		// D_MESG constant for hash function domain separation
		private const ushort D_MESG = 0x8181;

		/// <summary>
		/// Gets the Winternitz parameter for a given LM-OTS type
		/// </summary>
		/// <param name="typecode">The LM-OTS type code</param>
		/// <returns>The Winternitz parameter w</returns>
		public static int GetWinternitzParameter(uint typecode) {
			int w;

			switch (typecode) {
				case LMOTS_SHA256_N32_W1:
				case LMOTS_SHA256_N24_W1:
				case LMOTS_SHAKE_N32_W1:
				case LMOTS_SHAKE_N24_W1:
					w = 1;
					break;
				case LMOTS_SHA256_N32_W2:
				case LMOTS_SHA256_N24_W2:
				case LMOTS_SHAKE_N32_W2:
				case LMOTS_SHAKE_N24_W2:
					w = 2;
					break;
				case LMOTS_SHA256_N32_W4:
				case LMOTS_SHA256_N24_W4:
				case LMOTS_SHAKE_N32_W4:
				case LMOTS_SHAKE_N24_W4:
					w = 4;
					break;
				case LMOTS_SHA256_N32_W8:
				case LMOTS_SHA256_N24_W8:
				case LMOTS_SHAKE_N32_W8:
				case LMOTS_SHAKE_N24_W8:
					w = 8;
					break;
				default:
					throw new ArgumentException("Unsupported LM-OTS type");
			}
			return w;
		}

		/// <summary>
		/// Calculates p parameter based on n and w (RFC 8554 Section 4.1)
		/// p = ceil((8*n) / w) + ceil((floor(lg((8*n*(2^w - 1)) / w)) + 1) / w)
		/// </summary>
		/// <param name="n">Hash output length in bytes</param>
		/// <param name="w">Winternitz parameter</param>
		/// <returns>The parameter p</returns>
		public static int CalculateP(int n, int w) {
			int p;
			int u;
			int v;
			int ls;

			u = ((8 * n) + (w - 1)) / w;
#if !NET48
			ls = (int)Math.Floor(Math.Log2(8 * n * ((1 << w) - 1) / w));
#else
			ls = (int)Math.Floor(Math.Log((8 * n * ((1 << w) - 1)) / w, 2));
#endif
			v = (ls + 1 + (w - 1)) / w;
			p = u + v;
			return p;
		}

		/// <summary>
		/// RFC 8554 Algorithm 0: Generate an LM-OTS Private Key
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="q">The leaf number (4 bytes)</param>
		/// <param name="SEED">The private random seed</param>
		/// <param name="n">Hash output length in bytes</param>
		/// <param name="w">Winternitz parameter</param>
		/// <param name="p">Number of hash chains</param>
		/// <returns>The LM-OTS private key</returns>
		public static byte[][] GeneratePrivateKey(ILmsHashAlgorithm hash, byte[] I, uint q, byte[] SEED, int n, int w, int p) {
			byte[][] x;
			byte[] input;
			int i;

			x = new byte[p][];
			input = new byte[I.Length + 4 + 4 + 1 + SEED.Length];

			// Construct the input: I || u32str(q) || u16str(i) || u8str(0xff) || SEED
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(q, input, I.Length);
			input[I.Length + 4 + 2] = 0xff;
			Array.Copy(SEED, 0, input, I.Length + 4 + 4 + 1, SEED.Length);

			for (i = 0; i < p; i++) {
				LmsUtility.u16str((ushort)i, input, I.Length + 4);
				x[i] = hash.Hash(input);
			}

			return x;
		}

		/// <summary>
		/// RFC 8554 Algorithm 1a: Compute an LM-OTS Public Key Candidate from a Private Key, a Signature, and a Message
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="q">The leaf number</param>
		/// <param name="x">The LM-OTS private key (array of p n-byte strings)</param>
		/// <param name="n">Hash output length in bytes</param>
		/// <param name="w">Winternitz parameter</param>
		/// <param name="p">Number of hash chains</param>
		/// <returns>The LM-OTS public key</returns>
		public static byte[] GeneratePublicKey(ILmsHashAlgorithm hash, byte[] I, uint q, byte[][] x, int n, int w, int p) {
			byte[] tmp;
			byte[] y;
			byte[] input;
			int max_iter;
			int i;
			int j;

			tmp = new byte[n];
			y = new byte[p * n];
			input = new byte[I.Length + 4 + 2 + 1 + n];
			max_iter = (1 << w) - 1;

			// Set up the constant parts of input
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(q, input, I.Length);

			// For each element in the private key
			for (i = 0; i < p; i++) {
				Array.Copy(x[i], 0, tmp, 0, n);

				// Apply hash chain (2^w - 1) times
				for (j = 0; j < max_iter; j++) {
					LmsUtility.u16str((ushort)i, input, I.Length + 4);
					input[I.Length + 4 + 2] = (byte)j;
					Array.Copy(tmp, 0, input, I.Length + 4 + 2 + 1, n);
					tmp = hash.Hash(input);
				}

				Array.Copy(tmp, 0, y, i * n, n);
			}

			// Compute the public key as H(I || u32str(q) || u16str(D_PBLC) || y[0] || ... || y[p-1])
			input = new byte[I.Length + 4 + 2 + (p * n)];
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(q, input, I.Length);
			LmsUtility.u16str(D_PBLC, input, I.Length + 4);
			Array.Copy(y, 0, input, I.Length + 4 + 2, p * n);

			return hash.Hash(input);
		}

		/// <summary>
		/// RFC 8554 Algorithm 3: Generate an LM-OTS Signature
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="q">The leaf number</param>
		/// <param name="x">The LM-OTS private key</param>
		/// <param name="message">The message to sign</param>
		/// <param name="n">Hash output length in bytes</param>
		/// <param name="w">Winternitz parameter</param>
		/// <param name="p">Number of hash chains</param>
		/// <param name="typecode">The LM-OTS type code</param>
		/// <returns>The LM-OTS signature</returns>
		public static byte[] Sign(ILmsHashAlgorithm hash, byte[] I, uint q, byte[][] x, byte[] message, int n, int w, int p, uint typecode) {
			byte[] Q;
			byte[] Q_with_cksm;
			byte[] signature;
			byte[] tmp;
			byte[] input;
			byte[] randomizer;
			uint cksm;
			int i;
			int a;
			int sig_offset;

			// Hash the message with randomizer
			randomizer = new byte[n];
			Rng.randombytes(out randomizer, n);

			input = new byte[I.Length + 4 + 2 + randomizer.Length + message.Length];
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(q, input, I.Length);
			LmsUtility.u16str(D_MESG, input, I.Length + 4);
			Array.Copy(randomizer, 0, input, I.Length + 4 + 2, n);
			Array.Copy(message, 0, input, I.Length + 4 + 2 + n, message.Length);

			Q = hash.Hash(input);

			// Append checksum to Q
			cksm = LmsUtility.checksum(Q, w, n);
			Q_with_cksm = new byte[n + ((w == 8) ? 2 : (w == 4) ? 3 : (w == 2) ? 5 : 33)];
			Array.Copy(Q, 0, Q_with_cksm, 0, n);

			if (w == 8) {
				LmsUtility.u16str((ushort)cksm, Q_with_cksm, n);
			} else if (w == 4) {
				Q_with_cksm[n] = (byte)((cksm >> 16) & 0xff);
				LmsUtility.u16str((ushort)(cksm & 0xffff), Q_with_cksm, n + 1);
			} else if (w == 2) {
				Q_with_cksm[n] = (byte)((cksm >> 24) & 0xff);
				LmsUtility.u32str(cksm << 8, Q_with_cksm, n + 1);
			} else {
				LmsUtility.u32str(cksm, Q_with_cksm, n);
			}

			// Build signature: typecode || C || y[0] || ... || y[p-1]
			signature = new byte[4 + n + (p * n)];
			LmsUtility.u32str(typecode, signature, 0);
			Array.Copy(randomizer, 0, signature, 4, n);

			sig_offset = 4 + n;
			tmp = new byte[n];
			input = new byte[I.Length + 4 + 2 + 1 + n];

			// Prepare constant parts of input for hashing
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(q, input, I.Length);

			for (i = 0; i < p; i++) {
				a = LmsUtility.coef(Q_with_cksm, i, w);
				Array.Copy(x[i], 0, tmp, 0, n);

				// Apply hash chain 'a' times
				for (int j = 0; j < a; j++) {
					LmsUtility.u16str((ushort)i, input, I.Length + 4);
					input[I.Length + 4 + 2] = (byte)j;
					Array.Copy(tmp, 0, input, I.Length + 4 + 2 + 1, n);
					tmp = hash.Hash(input);
				}

				Array.Copy(tmp, 0, signature, sig_offset, n);
				sig_offset += n;
			}

			return signature;
		}

		/// <summary>
		/// RFC 8554 Algorithm 4b: Compute an LM-OTS Public Key Candidate from a Signature and Message
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="q">The leaf number</param>
		/// <param name="signature">The LM-OTS signature</param>
		/// <param name="message">The message that was signed</param>
		/// <param name="n">Hash output length in bytes</param>
		/// <param name="w">Winternitz parameter</param>
		/// <param name="p">Number of hash chains</param>
		/// <returns>The public key candidate</returns>
		public static byte[] ComputePublicKeyCandidate(ILmsHashAlgorithm hash, byte[] I, uint q, byte[] signature, byte[] message, int n, int w, int p) {
			byte[] Q;
			byte[] Q_with_cksm;
			byte[] Kc;
			byte[] tmp;
			byte[] input;
			byte[] randomizer;
			uint cksm;
			int max_iter;
			int i;
			int a;
			int sig_offset;

			// Extract randomizer (C) from signature
			randomizer = new byte[n];
			Array.Copy(signature, 4, randomizer, 0, n);

			// Hash the message with randomizer
			input = new byte[I.Length + 4 + 2 + randomizer.Length + message.Length];
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(q, input, I.Length);
			LmsUtility.u16str(D_MESG, input, I.Length + 4);
			Array.Copy(randomizer, 0, input, I.Length + 4 + 2, n);
			Array.Copy(message, 0, input, I.Length + 4 + 2 + n, message.Length);

			Q = hash.Hash(input);

			// Append checksum to Q
			cksm = LmsUtility.checksum(Q, w, n);
			Q_with_cksm = new byte[n + ((w == 8) ? 2 : (w == 4) ? 3 : (w == 2) ? 5 : 33)];
			Array.Copy(Q, 0, Q_with_cksm, 0, n);

			if (w == 8) {
				LmsUtility.u16str((ushort)cksm, Q_with_cksm, n);
			} else if (w == 4) {
				Q_with_cksm[n] = (byte)((cksm >> 16) & 0xff);
				LmsUtility.u16str((ushort)(cksm & 0xffff), Q_with_cksm, n + 1);
			} else if (w == 2) {
				Q_with_cksm[n] = (byte)((cksm >> 24) & 0xff);
				LmsUtility.u32str(cksm << 8, Q_with_cksm, n + 1);
			} else {
				LmsUtility.u32str(cksm, Q_with_cksm, n);
			}

			// Compute public key candidate
			Kc = new byte[p * n];
			tmp = new byte[n];
			input = new byte[I.Length + 4 + 2 + 1 + n];
			max_iter = (1 << w) - 1;

			// Prepare constant parts of input
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(q, input, I.Length);

			sig_offset = 4 + n;

			for (i = 0; i < p; i++) {
				a = LmsUtility.coef(Q_with_cksm, i, w);
				Array.Copy(signature, sig_offset, tmp, 0, n);

				// Apply hash chain from a to 2^w - 1
				for (int j = a; j < max_iter; j++) {
					LmsUtility.u16str((ushort)i, input, I.Length + 4);
					input[I.Length + 4 + 2] = (byte)j;
					Array.Copy(tmp, 0, input, I.Length + 4 + 2 + 1, n);
					tmp = hash.Hash(input);
				}

				Array.Copy(tmp, 0, Kc, i * n, n);
				sig_offset += n;
			}

			// Hash to produce the public key candidate
			input = new byte[I.Length + 4 + 2 + (p * n)];
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(q, input, I.Length);
			LmsUtility.u16str(D_PBLC, input, I.Length + 4);
			Array.Copy(Kc, 0, input, I.Length + 4 + 2, p * n);

			return hash.Hash(input);
		}
	}
}
