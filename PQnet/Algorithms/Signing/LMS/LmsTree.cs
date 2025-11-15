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
	/// RFC 8554 - LMS Merkle Tree Operations
	/// </summary>
	internal static class LmsTree {
		// D_LEAF constant for hash function domain separation
		private const ushort D_LEAF = 0x8282;

		// D_INTR constant for hash function domain separation
		private const ushort D_INTR = 0x8383;

		/// <summary>
		/// RFC 8554 Algorithm 5: Compute an Interior Node of a Merkle Tree
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="r">The tree height (level)</param>
		/// <param name="node_num">The node number at this level</param>
		/// <param name="left">The left child node value</param>
		/// <param name="right">The right child node value</param>
		/// <param name="n">Hash output length in bytes</param>
		/// <returns>The interior node value</returns>
		public static byte[] ComputeInteriorNode(ILmsHashAlgorithm hash, byte[] I, uint r, uint node_num, byte[] left, byte[] right, int n) {
			byte[] input;

			input = new byte[I.Length + 4 + 2 + n + n];
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(node_num, input, I.Length);
			LmsUtility.u16str(D_INTR, input, I.Length + 4);
			Array.Copy(left, 0, input, I.Length + 4 + 2, n);
			Array.Copy(right, 0, input, I.Length + 4 + 2 + n, n);

			return hash.Hash(input);
		}

		/// <summary>
		/// RFC 8554 Algorithm 6: Generate an LMS Leaf
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="r">The leaf number (at bottom of tree)</param>
		/// <param name="ots_public_key">The LM-OTS public key</param>
		/// <param name="n">Hash output length in bytes</param>
		/// <returns>The leaf value</returns>
		public static byte[] GenerateLeaf(ILmsHashAlgorithm hash, byte[] I, uint r, byte[] ots_public_key, int n) {
			byte[] input;

			input = new byte[I.Length + 4 + 2 + ots_public_key.Length];
			Array.Copy(I, 0, input, 0, I.Length);
			LmsUtility.u32str(r, input, I.Length);
			LmsUtility.u16str(D_LEAF, input, I.Length + 4);
			Array.Copy(ots_public_key, 0, input, I.Length + 4 + 2, ots_public_key.Length);

			return hash.Hash(input);
		}

		/// <summary>
		/// Build the complete Merkle tree for LMS
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="ots_keys">Array of LM-OTS private keys for each leaf</param>
		/// <param name="h">The height of the tree</param>
		/// <param name="n">Hash output length in bytes</param>
		/// <param name="w">Winternitz parameter</param>
		/// <param name="p">Number of hash chains in LM-OTS</param>
		/// <returns>The tree structure (array of levels, each level is array of nodes)</returns>
		public static byte[][][] BuildTree(ILmsHashAlgorithm hash, byte[] I, byte[][][] ots_keys, int h, int n, int w, int p) {
			byte[][][] tree;
			int num_leaves;
			int i;
			int level;
			int num_nodes;

			num_leaves = 1 << h;
			tree = new byte[h + 1][][];

			// Level 0 (leaves) - compute from OTS public keys
			tree[0] = new byte[num_leaves][];
			for (i = 0; i < num_leaves; i++) {
				byte[] ots_public_key;

				ots_public_key = LmOts.GeneratePublicKey(hash, I, (uint)i, ots_keys[i], n, w, p);
				tree[0][i] = GenerateLeaf(hash, I, (uint)i, ots_public_key, n);
			}

			// Interior levels
			for (level = 1; level <= h; level++) {
				num_nodes = 1 << (h - level);
				tree[level] = new byte[num_nodes][];

				for (i = 0; i < num_nodes; i++) {
					byte[] left;
					byte[] right;
					uint node_num;

					left = tree[level - 1][2 * i];
					right = tree[level - 1][(2 * i) + 1];
					node_num = (uint)((1 << (h - level)) + i);

					tree[level][i] = ComputeInteriorNode(hash, I, (uint)level, node_num, left, right, n);
				}
			}

			return tree;
		}

		/// <summary>
		/// Extract authentication path from the tree for a specific leaf
		/// RFC 8554 - Authentication path is the sibling nodes along the path from leaf to root
		/// </summary>
		/// <param name="tree">The complete Merkle tree</param>
		/// <param name="leaf_index">The index of the leaf</param>
		/// <param name="h">The height of the tree</param>
		/// <returns>The authentication path (array of h node values)</returns>
		public static byte[][] GetAuthenticationPath(byte[][][] tree, uint leaf_index, int h) {
			byte[][] auth_path;
			uint node_index;
			int level;

			auth_path = new byte[h][];
			node_index = leaf_index;

			for (level = 0; level < h; level++) {
				uint sibling_index;

				// Get the sibling at this level
				if ((node_index & 1) == 0) {
					// Node is left child, sibling is right
					sibling_index = node_index + 1;
				} else {
					// Node is right child, sibling is left
					sibling_index = node_index - 1;
				}

				auth_path[level] = tree[level][sibling_index];

				// Move to parent for next level
				node_index = node_index / 2;
			}

			return auth_path;
		}

		/// <summary>
		/// Verify an authentication path
		/// RFC 8554 Algorithm 6a: Compute root from leaf and authentication path
		/// </summary>
		/// <param name="hash">The hash algorithm to use</param>
		/// <param name="I">The 16-byte identifier</param>
		/// <param name="leaf_index">The index of the leaf</param>
		/// <param name="leaf_value">The value of the leaf (from OTS public key)</param>
		/// <param name="auth_path">The authentication path</param>
		/// <param name="h">The height of the tree</param>
		/// <param name="n">Hash output length in bytes</param>
		/// <returns>The computed root value</returns>
		public static byte[] ComputeRootFromPath(ILmsHashAlgorithm hash, byte[] I, uint leaf_index, byte[] leaf_value, byte[][] auth_path, int h, int n) {
			byte[] temp;
			uint node_num;
			int level;

			temp = new byte[n];
			Array.Copy(leaf_value, 0, temp, 0, n);
			node_num = leaf_index;

			for (level = 0; level < h; level++) {
				byte[] left;
				byte[] right;
				uint parent_node_num;

				parent_node_num = (uint)((1 << (h - level - 1)) + (node_num >> 1));

				if ((node_num & 1) == 0) {
					// Node is left child
					left = temp;
					right = auth_path[level];
				} else {
					// Node is right child
					left = auth_path[level];
					right = temp;
				}

				temp = ComputeInteriorNode(hash, I, (uint)(level + 1), parent_node_num, left, right, n);

				// Move to parent
				node_num = node_num >> 1;
			}

			return temp;
		}
	}
}
