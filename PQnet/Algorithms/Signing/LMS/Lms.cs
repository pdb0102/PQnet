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

namespace PQnet {
	/// <summary>
	/// RFC 8554 - LMS (Leighton-Micali Signature) implementation
	/// </summary>
	internal static class Lms {
		// LMS type constants (RFC 8554 Section 5.1)
		public const uint LMS_SHA256_M32_H5 = 5;
		public const uint LMS_SHA256_M32_H10 = 6;
		public const uint LMS_SHA256_M32_H15 = 7;
		public const uint LMS_SHA256_M32_H20 = 8;
		public const uint LMS_SHA256_M32_H25 = 9;

		/// <summary>
		/// Gets the tree height for a given LMS type
		/// </summary>
		/// <param name="typecode">The LMS type code</param>
		/// <returns>The tree height h</returns>
		public static int GetTreeHeight(uint typecode) {
			int h;

			switch (typecode) {
				case LMS_SHA256_M32_H5:
					h = 5;
					break;
				case LMS_SHA256_M32_H10:
					h = 10;
					break;
				case LMS_SHA256_M32_H15:
					h = 15;
					break;
				case LMS_SHA256_M32_H20:
					h = 20;
					break;
				case LMS_SHA256_M32_H25:
					h = 25;
					break;
				default:
					throw new ArgumentException("Unsupported LMS type");
			}
			return h;
		}

		/// <summary>
		/// RFC 8554 - Generate an LMS keypair
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="lms_typecode">The LMS type code</param>
		/// <param name="ots_typecode">The LM-OTS type code</param>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="SEED">The master seed</param>
		/// <param name="public_key">The generated public key</param>
		/// <param name="private_key">The generated private key</param>
		public static void GenerateKeyPair(ILmsHashAlgorithm hash, uint lms_typecode, uint ots_typecode, byte[] I, byte[] SEED, out byte[] public_key, out byte[] private_key) {
			int h;
			int n;
			int w;
			int p;
			int num_leaves;
			byte[][][] ots_keys;
			byte[][][] tree;
			byte[] root;
			int i;

			h = GetTreeHeight(lms_typecode);
			n = hash.OutputLength;
			w = LmOts.GetWinternitzParameter(ots_typecode);
			p = LmOts.CalculateP(n, w);
			num_leaves = 1 << h;

			// Generate all LM-OTS private keys
			ots_keys = new byte[num_leaves][][];
			for (i = 0; i < num_leaves; i++) {
				ots_keys[i] = LmOts.GeneratePrivateKey(hash, I, (uint)i, SEED, n, w, p);
			}

			// Build the Merkle tree
			tree = LmsTree.BuildTree(hash, I, ots_keys, h, n, w, p);

			// The root is the single node at the top level
			root = tree[h][0];

			// Build public key: LMS_type || LMOTS_type || I || T[1]
			public_key = new byte[4 + 4 + I.Length + n];
			LmsUtility.u32str(lms_typecode, public_key, 0);
			LmsUtility.u32str(ots_typecode, public_key, 4);
			Array.Copy(I, 0, public_key, 8, I.Length);
			Array.Copy(root, 0, public_key, 8 + I.Length, n);

			// Build private key: includes the tree, OTS keys, and metadata
			// Format: LMS_type || LMOTS_type || I || SEED || q (current leaf index)
			private_key = new byte[4 + 4 + I.Length + SEED.Length + 4];
			LmsUtility.u32str(lms_typecode, private_key, 0);
			LmsUtility.u32str(ots_typecode, private_key, 4);
			Array.Copy(I, 0, private_key, 8, I.Length);
			Array.Copy(SEED, 0, private_key, 8 + I.Length, SEED.Length);
			LmsUtility.u32str(0, private_key, 8 + I.Length + SEED.Length); // q starts at 0
		}

		/// <summary>
		/// RFC 8554 Algorithm 7: Generate an LMS Signature
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="private_key">The LMS private key</param>
		/// <param name="message">The message to sign</param>
		/// <param name="updated_private_key">The updated private key (with incremented q)</param>
		/// <returns>The LMS signature</returns>
		public static byte[] Sign(ILmsHashAlgorithm hash, byte[] private_key, byte[] message, out byte[] updated_private_key) {
			uint lms_typecode;
			uint ots_typecode;
			byte[] I;
			byte[] SEED;
			uint q;
			int h;
			int n;
			int w;
			int p;
			int num_leaves;
			byte[][] ots_key;
			byte[] ots_signature;
			byte[][][] ots_keys;
			byte[][][] tree;
			byte[][] auth_path;
			byte[] signature;
			int sig_offset;
			int i;

			// Parse private key
			lms_typecode = LmsUtility.strTou32(private_key, 0);
			ots_typecode = LmsUtility.strTou32(private_key, 4);
			I = new byte[16];
			Array.Copy(private_key, 8, I, 0, 16);
			n = hash.OutputLength;
			SEED = new byte[n];
			Array.Copy(private_key, 24, SEED, 0, n);
			q = LmsUtility.strTou32(private_key, 24 + n);

			h = GetTreeHeight(lms_typecode);
			w = LmOts.GetWinternitzParameter(ots_typecode);
			p = LmOts.CalculateP(n, w);
			num_leaves = 1 << h;

			// Check if we've exhausted all signatures
			if (q >= num_leaves) {
				throw new InvalidOperationException("LMS private key exhausted - all one-time signatures have been used");
			}

			// Generate the OTS private key for leaf q
			ots_key = LmOts.GeneratePrivateKey(hash, I, q, SEED, n, w, p);

			// Sign the message with LM-OTS
			ots_signature = LmOts.Sign(hash, I, q, ots_key, message, n, w, p, ots_typecode);

			// We need to rebuild the tree to get the authentication path
			// In a real implementation, this would be optimized to avoid rebuilding
			ots_keys = new byte[num_leaves][][];
			for (i = 0; i < num_leaves; i++) {
				ots_keys[i] = LmOts.GeneratePrivateKey(hash, I, (uint)i, SEED, n, w, p);
			}
			tree = LmsTree.BuildTree(hash, I, ots_keys, h, n, w, p);
			auth_path = LmsTree.GetAuthenticationPath(tree, q, h);

			// Build signature: q || LMOTS_signature || LMS_type || auth_path[0] || ... || auth_path[h-1]
			signature = new byte[4 + ots_signature.Length + 4 + (h * n)];
			sig_offset = 0;

			LmsUtility.u32str(q, signature, sig_offset);
			sig_offset += 4;

			Array.Copy(ots_signature, 0, signature, sig_offset, ots_signature.Length);
			sig_offset += ots_signature.Length;

			LmsUtility.u32str(lms_typecode, signature, sig_offset);
			sig_offset += 4;

			for (i = 0; i < h; i++) {
				Array.Copy(auth_path[i], 0, signature, sig_offset, n);
				sig_offset += n;
			}

			// Update private key with incremented q
			updated_private_key = new byte[private_key.Length];
			Array.Copy(private_key, 0, updated_private_key, 0, private_key.Length);
			LmsUtility.u32str(q + 1, updated_private_key, 24 + n);

			return signature;
		}

		/// <summary>
		/// RFC 8554 Algorithm 8: Verify an LMS Signature
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="public_key">The LMS public key</param>
		/// <param name="signature">The LMS signature</param>
		/// <param name="message">The message that was signed</param>
		/// <returns>True if the signature is valid, false otherwise</returns>
		public static bool Verify(ILmsHashAlgorithm hash, byte[] public_key, byte[] signature, byte[] message) {
			uint lms_typecode;
			uint ots_typecode;
			byte[] I;
			byte[] T1;
			uint q;
			byte[] ots_signature;
			uint sig_lms_typecode;
			byte[][] auth_path;
			int h;
			int n;
			int w;
			int p;
			int num_leaves;
			int sig_offset;
			int ots_sig_len;
			byte[] Kc;
			byte[] leaf;
			byte[] computed_root;
			int i;

			// Parse public key
			lms_typecode = LmsUtility.strTou32(public_key, 0);
			ots_typecode = LmsUtility.strTou32(public_key, 4);
			I = new byte[16];
			Array.Copy(public_key, 8, I, 0, 16);
			n = hash.OutputLength;
			T1 = new byte[n];
			Array.Copy(public_key, 24, T1, 0, n);

			h = GetTreeHeight(lms_typecode);
			w = LmOts.GetWinternitzParameter(ots_typecode);
			p = LmOts.CalculateP(n, w);
			num_leaves = 1 << h;

			// Parse signature
			q = LmsUtility.strTou32(signature, 0);

			// Check if q is valid
			if (q >= num_leaves) {
				return false;
			}

			// Extract OTS signature
			ots_sig_len = 4 + n + (p * n);
			ots_signature = new byte[ots_sig_len];
			Array.Copy(signature, 4, ots_signature, 0, ots_sig_len);

			sig_offset = 4 + ots_sig_len;

			// Extract and verify LMS type
			sig_lms_typecode = LmsUtility.strTou32(signature, sig_offset);
			sig_offset += 4;

			if (sig_lms_typecode != lms_typecode) {
				return false;
			}

			// Extract authentication path
			auth_path = new byte[h][];
			for (i = 0; i < h; i++) {
				auth_path[i] = new byte[n];
				Array.Copy(signature, sig_offset, auth_path[i], 0, n);
				sig_offset += n;
			}

			// Compute the OTS public key candidate
			Kc = LmOts.ComputePublicKeyCandidate(hash, I, q, ots_signature, message, n, w, p);

			// Compute the leaf from the OTS public key candidate
			leaf = LmsTree.GenerateLeaf(hash, I, q, Kc, n);

			// Compute the root using the authentication path
			computed_root = LmsTree.ComputeRootFromPath(hash, I, q, leaf, auth_path, h, n);

			// Verify that the computed root matches the public key root
			if (computed_root.Length != T1.Length) {
				return false;
			}

			for (i = 0; i < n; i++) {
				if (computed_root[i] != T1[i]) {
					return false;
				}
			}

			return true;
		}
	}
}
