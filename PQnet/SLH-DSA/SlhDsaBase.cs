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
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;

using PQnet.Digest;

namespace PQnet {
	public abstract partial class SlhDsaBase : ISecurityCategory {
		private IHashAlgorithm hash;
		private int n;
		private int h;
		private int d;
		private int h_prime;
		private int a;
		private int k;
		private int lg_w;
		private int m;

		// Winternitz
		private int w;             // FIPS 205 (5.1)
		private int len1;          // FIPS 205 (5.2)
		private int len2;          // FIPS 205 (5.3)
		private int len;           // FIPS 205 (5.4)

		private int signature_size;

		private int tree_bits;
		private int leaf_bits;

		private string name;

		/// <summary>
		/// Initializes a new instance of the <see cref="SlhDsaBase"/> class.
		/// </summary>
		/// <param name="hash"></param>
		/// <param name="n"></param>
		/// <param name="h"></param>
		/// <param name="d"></param>
		/// <param name="hp"></param>
		/// <param name="a"></param>
		/// <param name="k"></param>
		/// <param name="lg_w"></param>
		/// <param name="m"></param>
		public SlhDsaBase(IHashAlgorithm hash, int n = 16, int h = 66, int d = 22, int hp = 3, int a = 6, int k = 33, int lg_w = 4, int m = 34) {
			this.hash = hash;
			this.n = n;
			this.h = h;
			this.d = d;
			this.h_prime = hp;
			this.a = a;
			this.k = k;
			this.lg_w = lg_w;
			this.m = m;

			w = 1 << lg_w;
			len1 = ((8 * n) + (lg_w - 1)) / lg_w;
#if !NET48
			len2 = ((int)Math.Log2(len1 * (w - 1)) / lg_w) + 1;
#else
			len2 = ((int)Math.Log(len1 * (w - 1), 2) / lg_w) + 1;
#endif
			len = len1 + len2;

			SeedBytes = 3 * n;
			PublicKeyBytes = 2 * n;
			PrivateKeyBytes = (2 * n) + PublicKeyBytes;

			signature_size = (1 + (k * (1 + a)) + h + (d * len)) * n;

			leaf_bits = h / d;
			tree_bits = leaf_bits * (d - 1);

			name = $"SLH-DSA-{hash.Name}-{8 * n}f";
		}

		/// <summary>
		/// Gets or sets whether signature generation is deterministic
		/// </summary>
		public bool Deterministic { get; set; }

		/// <summary>
		/// Gets the size, in bytes, of the private key
		/// </summary>
		public int PrivateKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the public key
		/// </summary>
		public int PublicKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the seed used for key generation
		/// </summary>
		public int SeedBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the signature
		/// </summary>
		public int SignatureBytes {
			get {
				return signature_size;
			}
		}

		/// <summary>
		/// Gets the name of the algorithm
		/// </summary>
		public abstract string Name { get; }

		/// <summary>
		/// Gets the NIST security category of the cryptographic algorithm.
		/// </summary>
		public abstract int NistSecurityCategory { get; }

		/// <summary>
		/// FIPS 205 Algorithm 2 
		/// </summary>
		/// <param name="x"></param>
		/// <param name="n"></param>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static long toInt(byte[] x, int n) {
			long l;

			l = 0;
			for (int i = 0; i < n; i++) {
				l = (l << 8) | x[i];
			}
			return l;
		}

		/// <summary>
		/// FIPS 205 Algorithm 3 
		/// </summary>
		/// <param name="x">integer</param>
		/// <param name="n">length</param>
		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private static byte[] toByte(long x, int n) {
			byte[] b;

			b = new byte[n];
			for (int i = 0; i < n; i++) {
				b[i] = (byte)(x >> (8 * (n - 1 - i)));
			}

			return b;
		}

		/// <summary>
		/// FIPS 205 Algorithm 4 - Computes the base 2𝑏 representation of 𝑋.
		/// </summary>
		/// <param name="x">Byte string 𝑋 of length at least ⌈𝑜𝑢𝑡_𝑙𝑒𝑛⋅𝑏 / 8 ⌉</param>
		/// <param name="b">Integer</param>
		/// <param name="out_len">output length</param>
		/// <returns>Array of 𝑜𝑢𝑡_𝑙𝑒𝑛 integers in the range[0, … , 2𝑏 − 1]</returns>
		private long[] base_2b(byte[] x, int b, uint out_len) {
			int in_offset;
			int bits;
			int total;
			long[] baseb;
			int mask;

			in_offset = 0;
			bits = 0;
			total = 0;
			baseb = new long[out_len];

			mask = (1 << b) - 1; // Precompute the mask for mod 2^b

			for (int j = 0; j < out_len; j++) {
				while (bits < b) {
					total = (total << 8) | x[in_offset++];
					bits += 8;
				}
				bits -= b;
				baseb[j] = (uint)((total >> bits) & mask);
			}

			return baseb;
		}

		/// <summary>
		/// FIPS 205 Algorithm 5 - Chaining function used in WOTS+
		/// </summary>
		/// <param name="x">Input string</param>
		/// <param name="i">Start index</param>
		/// <param name="s">Number of steps</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>Value of F iterated 𝑠 times on 𝑋</returns>
		private byte[] chain(byte[] x, int i, int s, byte[] pk_seed, IAddress adrs) {
			byte[] tmp;

			tmp = x;

			for (int j = i; j < i + s; j++) {
				adrs.SetHashAddress((uint)j);
				tmp = hash.f(pk_seed, adrs, tmp);
			}

			return tmp;
		}

		/// <summary>
		/// FIPS 205 Algorithm 6 - Generates a WOTS+ public key
		/// </summary>
		/// <param name="sk_seed">Secret seed</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>WOTS+ public key 𝑝𝑘</returns>
		private byte[] wots_pkGen(byte[] sk_seed, byte[] pk_seed, IAddress adrs) {
			IAddress sk_adrs;
			IAddress wotspk_adrs;
			byte[] sk;
			byte[] pk;
			List<byte> tmp;

			sk_adrs = adrs.Clone();
			sk_adrs.SetTypeAndClear(AddressType.WotsPrf);
			sk_adrs.SetKeyPairAddress(adrs.KeyPairAddress);

			tmp = new List<byte>();

			for (int i = 0; i < len; i++) {
				sk_adrs.SetChainAddress((uint)i);
				sk = hash.prf(pk_seed, sk_seed, sk_adrs);
				adrs.SetChainAddress((uint)i);
				tmp.AddRange(chain(sk, 0, w - 1, pk_seed, adrs));
			}

			wotspk_adrs = adrs.Clone();
			wotspk_adrs.SetTypeAndClear(AddressType.WotsPk);
			wotspk_adrs.SetKeyPairAddress(adrs.KeyPairAddress);

			pk = hash.t_len(pk_seed, wotspk_adrs, tmp.ToArray());

			return pk;
		}

		/// <summary>
		/// FIPS 205 Algorithm 7 - Generates a WOTS+ signature on an 𝑛-byte message
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="sk_seed">Secret seed</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>WOTS+ signature 𝑠𝑖𝑔</returns>
		private byte[] wots_sign(byte[] m, byte[] sk_seed, byte[] pk_seed, IAddress adrs) {
			long csum;
			List<long> msg;
			byte[] sk;
			List<byte> sig;
			IAddress sk_adrs;

			csum = 0;
			msg = new List<long>(base_2b(m, lg_w, (uint)len1));
			sig = new List<byte>();

			for (int i = 0; i < len1; i++) {
				csum += w - 1 - msg[i];
			}

			csum <<= (8 - (len2 * lg_w % 8)) % 8;
			msg.AddRange(base_2b(toByte(csum, ((len2 * lg_w) + 7) / 8), lg_w, (uint)len2));

			sk_adrs = adrs.Clone();
			sk_adrs.SetTypeAndClear(AddressType.WotsPrf);
			sk_adrs.SetKeyPairAddress(adrs.KeyPairAddress);
			for (int i = 0; i < len; i++) {
				sk_adrs.SetChainAddress((uint)i);
				sk = hash.prf(pk_seed, sk_seed, sk_adrs);
				adrs.SetChainAddress((uint)i);
				sig.AddRange(chain(sk, 0, (int)msg[i], pk_seed, adrs));
			}

			return sig.ToArray();
		}

		/// <summary>
		/// FIPS 205 Algorithm 8 - Computes a WOTS+ public key from a message and its signature
		/// </summary>
		/// <param name="sig">WOTS+ signature</param>
		/// <param name="m">Message</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>WOTS+ public key 𝑝𝑘𝑠𝑖𝑔 derived from 𝑠𝑖𝑔</returns>
		private byte[] wots_pkFromSig(byte[] sig, byte[] m, byte[] pk_seed, IAddress adrs) {
			IAddress wotspk_adrs;
			List<long> msg;
			List<byte> tmp;
			byte[] sig_i;
			long csum;

			sig_i = new byte[n];

			byte[] GetSigI(int i) {
				Array.Copy(sig, i * n, sig_i, 0, n);
				return sig_i;
			}

			csum = 0;
			tmp = new List<byte>();
			msg = new List<long>();
			msg.AddRange(base_2b(m, lg_w, (uint)len1));
			for (int i = 0; i < len1; i++) {
				csum += w - 1 - msg[i];
			}

			csum <<= (8 - (len2 * lg_w % 8)) % 8;
			msg.AddRange(base_2b(toByte(csum, ((len2 * lg_w) + 7) / 8), lg_w, (uint)len2));

			for (int i = 0; i < len; i++) {
				adrs.SetChainAddress((uint)i);
				tmp.AddRange(chain(GetSigI(i), (int)msg[i], (int)(w - 1 - msg[i]), pk_seed, adrs));
			}

			wotspk_adrs = adrs.Clone();
			wotspk_adrs.SetTypeAndClear(AddressType.WotsPk);
			wotspk_adrs.SetKeyPairAddress(adrs.KeyPairAddress);
			return hash.t_len(pk_seed, wotspk_adrs, tmp.ToArray());    // pk_sig
		}

		/// <summary>
		/// FIPS 205 Algorithm 9 - Computes the root of a Merkle subtree of WOTS+ public keys
		/// </summary>
		/// <param name="sk_seed">Secret seed</param>
		/// <param name="i">Target node index</param>
		/// <param name="z">Target node height</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>𝑛-byte root 𝑛𝑜𝑑𝑒</returns>
		private byte[] xmss_node(byte[] sk_seed, long i, long z, byte[] pk_seed, IAddress adrs) {
			if (z == 0) {
				adrs.SetTypeAndClear(AddressType.WotsHash);
				adrs.SetKeyPairAddress((uint)i);
				return wots_pkGen(sk_seed, pk_seed, adrs);  // node
			} else {
				byte[] lnode;
				byte[] rnode;

				lnode = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
				rnode = xmss_node(sk_seed, (2 * i) + 1, z - 1, pk_seed, adrs);
				adrs.SetTypeAndClear(AddressType.Tree);
				adrs.SetTreeHeight((uint)z);
				adrs.SetTreeIndex((uint)i);
				return hash.h(pk_seed, adrs, lnode.Concat(rnode).ToArray());    // node
			}
		}

		/// <summary>
		/// FIPS 205 Algorithm 10 - Generates an XMSS signature
		/// </summary>
		/// <param name="m">𝑛-byte message</param>
		/// <param name="sk_seed">Secret seed</param>
		/// <param name="idx">Index</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH)</returns>
		private byte[] xmss_sign(byte[] m, byte[] sk_seed, long idx, byte[] pk_seed, IAddress adrs) {
			List<byte> auth;
			List<byte> sig;
			long k;

			auth = new List<byte>();
			for (int j = 0; j < h_prime; j++) {
				k = (idx >> j) ^ 1;
				auth.AddRange(xmss_node(sk_seed, k, j, pk_seed, adrs));
			}

			adrs.SetTypeAndClear(AddressType.WotsHash);
			adrs.SetKeyPairAddress((uint)idx);

			sig = new List<byte>();
			sig.AddRange(wots_sign(m, sk_seed, pk_seed, adrs));
			sig.AddRange(auth);
			return sig.ToArray();
		}

		/// <summary>
		/// FIPS 205 Algorithm 11 - Computes an XMSS public key from an XMSS signature
		/// </summary>
		/// <param name="idx">Index</param>
		/// <param name="sig_xmss">XMSS signature SIG𝑋𝑀𝑆𝑆 = (𝑠𝑖𝑔 ∥ AUTH)</param>
		/// <param name="m">𝑛-byte message</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>𝑛-byte root value 𝑛𝑜𝑑𝑒[0]</returns>
		private byte[] xmss_pkFromSig(long idx, byte[] sig_xmss, byte[] m, byte[] pk_seed, IAddress adrs) {
			byte[] sig;
			byte[] auth;
			byte[] node_0;
			byte[] node_1;
			byte[] auth_k;

			auth_k = new byte[n];

			adrs.SetTypeAndClear(AddressType.WotsHash);
			adrs.SetKeyPairAddress((uint)idx);
			sig = new byte[len * n];
			Array.Copy(sig_xmss, 0, sig, 0, sig.Length);
			auth = new byte[sig_xmss.Length - (len * n)];
			Array.Copy(sig_xmss, sig.Length, auth, 0, auth.Length);
			node_0 = wots_pkFromSig(sig, m, pk_seed, adrs);

			adrs.SetTypeAndClear(AddressType.Tree);
			adrs.SetTreeIndex((uint)idx);
			for (int k = 0; k < h_prime; k++) {
				adrs.SetTreeHeight((uint)k + 1);
				Array.Copy(auth, k * n, auth_k, 0, n);

				if (((idx >> k) % 2) == 0) {
					adrs.SetTreeIndex(adrs.TreeIndex >> 1);
					node_1 = hash.h(pk_seed, adrs, node_0.Concat(auth_k).ToArray());
				} else {
					adrs.SetTreeIndex((adrs.TreeIndex - 1) >> 1);
					node_1 = hash.h(pk_seed, adrs, auth_k.Concat(node_0).ToArray());
				}
				node_0 = node_1;
			}

			return node_0;
		}

		/// <summary>
		/// FIPS 205 Algorithm 12 - Generates a hypertree signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="sk_seed">Secret seed</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="idx_tree">Tree index</param>
		/// <param name="idx_leaf">Leaf index</param>
		/// <returns>HT signature SIG𝐻𝑇</returns>
		private byte[] ht_sign(byte[] m, byte[] sk_seed, byte[] pk_seed, long idx_tree, long idx_leaf) {
			IAddress adrs;
			byte[] sig_tmp;
			byte[] sig_ht;
			byte[] root;
			int mask;

			adrs = GetAddress();
			adrs.SetTreeAddress((ulong)idx_tree);
			sig_tmp = xmss_sign(m, sk_seed, idx_leaf, pk_seed, adrs);
			sig_ht = sig_tmp;
			root = xmss_pkFromSig(idx_leaf, sig_tmp, m, pk_seed, adrs);

			mask = (1 << h_prime) - 1;
			for (int j = 1; j < d; j++) {
				idx_leaf = idx_tree & mask;
				idx_tree = (long)((ulong)idx_tree >> h_prime);
				adrs.SetLayerAddress((uint)j);
				adrs.SetTreeAddress((ulong)idx_tree);
				sig_tmp = xmss_sign(root, sk_seed, idx_leaf, pk_seed, adrs);
				sig_ht = sig_ht.Concat(sig_tmp).ToArray();
				if (j < (d - 1)) {
					root = xmss_pkFromSig(idx_leaf, sig_tmp, root, pk_seed, adrs);
				}
			}
			return sig_ht;
		}

		/// <summary>
		/// FIPS 205 Algorithm 13 - Verifies a hypertree signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="sig_ht">Signature SIG𝐻𝑇</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="idx_tree">Tree index</param>
		/// <param name="idx_leaf">Leaf index</param>
		/// <param name="pk_root">HT public key</param>
		/// <returns><c>true</c> if the signature is correct, <c>false</c> otherwise</returns>
		private bool ht_verify(byte[] m, byte[] sig_ht, byte[] pk_seed, long idx_tree, long idx_leaf, byte[] pk_root) {
			IAddress adrs;
			byte[] sig_tmp;
			byte[] node;
			int mask;

			adrs = GetAddress();
			adrs.SetTreeAddress((ulong)idx_tree);

			sig_tmp = new byte[(h_prime + len) * n];
			Array.Copy(sig_ht, 0, sig_tmp, 0, sig_tmp.Length);
			node = xmss_pkFromSig(idx_leaf, sig_tmp, m, pk_seed, adrs);

			mask = (1 << h_prime) - 1;
			for (int j = 1; j < d; j++) {
				idx_leaf = idx_tree & mask;
				idx_tree = (long)((ulong)idx_tree >> h_prime);
				adrs.SetLayerAddress((uint)j);
				adrs.SetTreeAddress((ulong)idx_tree);
				sig_tmp = new byte[(h_prime + len) * n];
				Array.Copy(sig_ht, j * (h_prime + len) * n, sig_tmp, 0, sig_tmp.Length);
				node = xmss_pkFromSig(idx_leaf, sig_tmp, node, pk_seed, adrs);
			}

			if (node.Length != pk_root.Length) {
				return false;
			}
			for (int i = 0; i < node.Length; i++) {
				if (node[i] != pk_root[i]) {
					return false;
				}
			}

			return true;
		}

		/// <summary>
		/// FIPS 205 Algorithm 14 - Generates a FORS private-key value
		/// </summary>
		/// <param name="sk_seed">Secret seed</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <param name="idx">Secret key index</param>
		/// <returns>𝑛-byte FORS private-key value</returns>
		private byte[] fors_skGen(byte[] sk_seed, byte[] pk_seed, IAddress adrs, int idx) {
			IAddress sk_adrs;

			sk_adrs = adrs.Clone();
			sk_adrs.SetTypeAndClear(AddressType.ForsPrf);
			sk_adrs.SetKeyPairAddress(adrs.KeyPairAddress);
			sk_adrs.SetTreeIndex((uint)idx);
			return hash.prf(pk_seed, sk_seed, sk_adrs);
		}

		/// <summary>
		/// FIPS 205 Algorithm 15 - Computes the root of a Merkle subtree of FORS public values
		/// </summary>
		/// <param name="sk_seed">Secret seed</param>
		/// <param name="i">Target node index</param>
		/// <param name="z">Target node height</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>𝑛-byte root 𝑛𝑜𝑑𝑒</returns>
		private byte[] fors_node(byte[] sk_seed, int i, int z, byte[] pk_seed, IAddress adrs) {
			byte[] sk;
			byte[] node;
			byte[] lnode;
			byte[] rnode;

			if (z == 0) {
				sk = fors_skGen(sk_seed, pk_seed, adrs, i);
				adrs.SetTreeHeight(0);
				adrs.SetTreeIndex((uint)i);
				node = hash.f(pk_seed, adrs, sk);
			} else {
				lnode = fors_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
				rnode = fors_node(sk_seed, (2 * i) + 1, z - 1, pk_seed, adrs);
				adrs.SetTreeHeight((uint)z);
				adrs.SetTreeIndex((uint)i);
				node = hash.h(pk_seed, adrs, lnode.Concat(rnode).ToArray());
			}
			return node;
		}

		/// <summary>
		/// FIPS 205 Algorithm 16 - Generates a FORS signature
		/// </summary>
		/// <param name="md">Message digest</param>
		/// <param name="sk_seed">Secret seed</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>FORS signature SIG𝐹𝑂𝑅𝑆</returns>
		private byte[] fors_sign(byte[] md, byte[] sk_seed, byte[] pk_seed, IAddress adrs) {
			List<byte> sig_fors;
			long[] indices;
			long s;

			sig_fors = new List<byte>();
			indices = base_2b(md, a, (uint)k);
			for (int i = 0; i < k; i++) {
				sig_fors.AddRange(fors_skGen(sk_seed, pk_seed, adrs, (int)((i << a) + indices[i])));

				for (int j = 0; j < a; j++) {
					s = (indices[i] >> j) ^ 1;
					sig_fors.AddRange(fors_node(sk_seed, (int)((i << (a - j)) + s), j, pk_seed, adrs));
				}
			}
			return sig_fors.ToArray();
		}

		/// <summary>
		/// FIPS 205 Algorithm 17 - Computes a FORS public key from a FORS signature
		/// </summary>
		/// <param name="sig_fors">FORS signature SIG𝐹𝑂𝑅𝑆</param>
		/// <param name="md">Message digest</param>
		/// <param name="pk_seed">Public seed</param>
		/// <param name="adrs">Address</param>
		/// <returns>FORS public key</returns>
		private byte[] fors_pkFromSig(byte[] sig_fors, byte[] md, byte[] pk_seed, IAddress adrs) {
			List<byte> sig;
			long[] indices;
			byte[] sk;
			byte[] auth;
			byte[] sk_buf;
			byte[] auth_buf;
			List<byte> root;
			byte[] node_0;
			byte[] node_1;
			byte[] auth_j;
			IAddress forspk_adrs;

			byte[] getSk(int i) {
				Array.Copy(sig_fors, i * (a + 1) * n, sk_buf, 0, n);
				return sk_buf;
			}

			byte[] getAuth(int i) {
				Array.Copy(sig_fors, ((i * (a + 1)) + 1) * n, auth_buf, 0, auth_buf.Length);
				return auth_buf;
			}

			root = new List<byte>();
			sk_buf = new byte[n];
			auth_buf = new byte[a * n];
			auth_j = new byte[n];
			sig = new List<byte>();

			indices = base_2b(md, a, (uint)k);

			for (int i = 0; i < k; i++) {
				sk = getSk(i);
				adrs.SetTreeHeight(0);
				adrs.SetTreeIndex((uint)((i << a) + indices[i]));
				node_0 = hash.f(pk_seed, adrs, sk);

				auth = getAuth(i);
				for (int j = 0; j < a; j++) {
					Array.Copy(auth, j * n, auth_j, 0, n);
					adrs.SetTreeHeight((uint)j + 1);
					if (((indices[i] >> j) % 2) == 0) {
						adrs.SetTreeIndex(adrs.TreeIndex >> 1);
						node_1 = hash.h(pk_seed, adrs, node_0.Concat(auth_j).ToArray());
					} else {
						adrs.SetTreeIndex((adrs.TreeIndex - 1) >> 1);
						node_1 = hash.h(pk_seed, adrs, auth_j.Concat(node_0).ToArray());
					}
					node_0 = node_1;
				}
				root.AddRange(node_0);
			}

			forspk_adrs = adrs.Clone();
			forspk_adrs.SetTypeAndClear(AddressType.ForsRoots);
			forspk_adrs.SetKeyPairAddress(adrs.KeyPairAddress);
			return hash.t_len(pk_seed, forspk_adrs, root.ToArray());
		}

		/// <summary>
		/// FIPS 205 Algorithm 18 - Generates an SLH-DSA key pair
		/// </summary>
		/// <param name="sk_seed">Secret seed</param>
		/// <param name="sk_prf">PRF key</param>
		/// <param name="pk_seed">Public seed</param>
		/// <returns>SLH-DSA key pair (SK, PK)</returns>
		internal (byte[], byte[]) slh_keygen_internal(byte[] sk_seed, byte[] sk_prf, byte[] pk_seed) {
			IAddress adrs;
			byte[] pk_root;

			adrs = GetAddress();
			adrs.SetLayerAddress((uint)d - 1);
			pk_root = xmss_node(sk_seed, 0, h_prime, pk_seed, adrs);


			return (sk_seed.Concat(sk_prf).Concat(pk_seed).Concat(pk_root).ToArray(), pk_seed.Concat(pk_root).ToArray());
		}


		/// <summary>
		/// FIPS 205 Algorithm 19 - Generates an SLH-DSA signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="sk">Private key (SK.seed, SK.prf, PK.seed, PK.root)</param>
		/// <param name="addrnd">Additional randomness, or <c>null</c></param>
		/// <returns>SLH-DSA signature SIG</returns>
		internal byte[] slh_sign_internal(byte[] m, byte[] sk, byte[] addrnd) {
			IAddress adrs;
			byte[] opt_rand;
			byte[] sk_seed;
			byte[] sk_prf;
			byte[] pk_seed;
			byte[] pk_root;
			byte[] r;
			byte[] digest;

			byte[] md;
			byte[] tmp_idx_tree;
			byte[] tmp_idx_leaf;
			long idx_tree;
			long idx_leaf;

			int ka;
			int hd;
			int h_hd;

			byte[] sig_fors;
			byte[] sig_ht;
			byte[] pk_fors;
			List<byte> sig;

			sig = new List<byte>();

			ka = ((k * a) + 7) / 8;
			hd = h / d;
			h_hd = h - hd;

			byte[] GetDigestPart(int start, int length) {
				byte[] result;

				result = new byte[length];
				Array.Copy(digest, start, result, 0, length);
				return result;
			}

			SplitSk(sk, out sk_seed, out sk_prf, out pk_seed, out pk_root);

			adrs = GetAddress();
			if (!Deterministic) {
				opt_rand = addrnd;
			} else {
				opt_rand = pk_seed;
			}

			r = hash.prf_msg(sk_prf, opt_rand, m);
			sig.AddRange(r);

			digest = hash.h_msg(r, pk_seed, pk_root, m);
			md = GetDigestPart(0, ka);
			tmp_idx_tree = GetDigestPart(ka, (h_hd + 7) / 8);
			tmp_idx_leaf = GetDigestPart(ka + ((h_hd + 7) / 8), (hd + 7) / 8);

			idx_tree = toInt(tmp_idx_tree, (h_hd + 7) / 8);
			if (h_hd < 64) {
				idx_tree = (long)((ulong)idx_tree % (1ul << h_hd));
			}
			idx_leaf = toInt(tmp_idx_leaf, (hd + 7) / 8);
			if (hd < 32) {
				idx_leaf %= (long)1 << hd;
			}

			adrs.SetTreeAddress((ulong)idx_tree);
			adrs.SetTypeAndClear(AddressType.ForsTree);
			adrs.SetKeyPairAddress((uint)idx_leaf);

			sig_fors = fors_sign(md, sk_seed, pk_seed, adrs);
			sig.AddRange(sig_fors);

			pk_fors = fors_pkFromSig(sig_fors, md, pk_seed, adrs);
			sig_ht = ht_sign(pk_fors, sk_seed, pk_seed, idx_tree, idx_leaf);
			sig.AddRange(sig_ht);

			return sig.ToArray();
		}

		/// <summary>
		/// FIPS 205 Algorithm 20 - Verifies an SLH-DSA signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="sig">Signature</param>
		/// <param name="pk">Public key (PK.seed, PK.root)</param>
		/// <returns><c>true</c> if the signature is valid, <c>false</c> otherwise</returns>
		internal bool slh_verify_internal(byte[] m, byte[] sig, byte[] pk) {
			IAddress adrs;
			byte[] pk_seed;
			byte[] pk_root;
			byte[] r;
			byte[] digest;
			byte[] sig_fors;
			byte[] sig_ht;
			byte[] pk_fors;

			byte[] md;
			byte[] tmp_idx_tree;
			byte[] tmp_idx_leaf;
			long idx_tree;
			long idx_leaf;

			int ka;
			int hd;
			int h_hd;

			SplitPk(pk, out pk_seed, out pk_root);

			if (sig.Length != signature_size) {
				return false;
			}

			ka = ((k * a) + 7) / 8;
			hd = h / d;
			h_hd = h - hd;

			byte[] GetDigestPart(int start, int length) {
				byte[] result;

				result = new byte[length];
				Array.Copy(digest, start, result, 0, length);
				return result;
			}

			adrs = GetAddress();
			r = new byte[n];
			Array.Copy(sig, 0, r, 0, n);

			sig_fors = new byte[k * (1 + a) * n];
			Array.Copy(sig, n, sig_fors, 0, sig_fors.Length);
			sig_ht = new byte[sig.Length - sig_fors.Length - n];
			Array.Copy(sig, n + sig_fors.Length, sig_ht, 0, sig_ht.Length);

			digest = hash.h_msg(r, pk_seed, pk_root, m);
			md = GetDigestPart(0, ka);
			tmp_idx_tree = GetDigestPart(ka, (h_hd + 7) / 8);
			tmp_idx_leaf = GetDigestPart(ka + ((h_hd + 7) / 8), (hd + 7) / 8);

			idx_tree = toInt(tmp_idx_tree, (h_hd + 7) / 8);
			if (h_hd < 64) {
				idx_tree = (long)((ulong)idx_tree % (1ul << h_hd));
			}
			idx_leaf = toInt(tmp_idx_leaf, (hd + 7) / 8);
			if (hd < 32) {
				idx_leaf %= (long)1 << hd;
			}

			adrs.SetTreeAddress((ulong)idx_tree);
			adrs.SetTypeAndClear(AddressType.ForsTree);
			adrs.SetKeyPairAddress((uint)idx_leaf);

			pk_fors = fors_pkFromSig(sig_fors, md, pk_seed, adrs);
			return ht_verify(pk_fors, sig_ht, pk_seed, idx_tree, idx_leaf, pk_root);
		}

		/// <summary>
		/// FIPS 205 Algorithm 21 - Generates an SLH-DSA key pair
		/// </summary>
		/// <param name="sk">Receives private key</param>
		/// <param name="pk">Receives public key</param>
		public void slh_keygen(out byte[] sk, out byte[] pk) {
			byte[] sk_seed;
			byte[] sk_prf;
			byte[] pk_seed;

			Rng.randombytes(out sk_seed, n);
			Rng.randombytes(out sk_prf, n);
			Rng.randombytes(out pk_seed, n);

			(sk, pk) = slh_keygen_internal(sk_seed, sk_prf, pk_seed);
		}

		/// <summary>
		/// FIPS 205 Algorithm 22 - Generates a pure SLH-DSA signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="ctx">Context string</param>
		/// <param name="sk">Private key</param>
		/// <returns>SLH-DSA signature SIG</returns>
		/// <exception cref="ArgumentException"><paramref name="ctx"/> is longer than 255 bytes</exception>
		public byte[] slh_sign(byte[] m, byte[] ctx, byte[] sk) {
			byte[] addrnd;
			byte[] m_prime;

			if (ctx == null) {
				ctx = Array.Empty<byte>();
			}
			if (ctx.Length > 255) {
				throw new ArgumentException("Context too long");
			}

			if (!Deterministic) {
				Rng.randombytes(out addrnd, n);
			} else {
				addrnd = null;
			}

			m_prime = new byte[m.Length + ctx.Length + 2];
			m_prime[0] = 0;
			m_prime[1] = (byte)ctx.Length;
			Array.Copy(ctx, 0, m_prime, 2, ctx.Length);
			Array.Copy(m, 0, m_prime, ctx.Length + 2, m.Length);

			return slh_sign_internal(m_prime, sk, addrnd);
		}

		/// <summary>
		/// FIPS 205 Algorithm 23 - Generates a pre-hash SLH-DSA signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="ctx">Context string</param>
		/// <param name="ph">Pre-hash function</param>
		/// <param name="sk">Private key</param>
		/// <returns>SLH-DSA signature SIG</returns>
		/// <exception cref="ArgumentException"><paramref name="ctx"/> is longer than 255 bytes, or <paramref name="ph"/> is not supported</exception>
		public byte[] hash_slh_sign(byte[] m, byte[] ctx, PreHashFunction ph, byte[] sk) {
			byte[] addrnd;
			byte[] m_prime;
			byte[] ph_m;
			byte[] oid;

			if (ctx == null) {
				ctx = Array.Empty<byte>();
			}
			if (ctx.Length > 255) {
				throw new ArgumentException("Context too long");
			}

			if (!Deterministic) {
				Rng.randombytes(out addrnd, n);
			} else {
				addrnd = null;
			}

			switch (ph) {
				case PreHashFunction.SHA224:
					throw new NotImplementedException("Not yet implemented");

				case PreHashFunction.SHA256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
#if !NET48
					ph_m = System.Security.Cryptography.SHA256.HashData(m);
#else
					using (System.Security.Cryptography.SHA256Cng SHA = new System.Security.Cryptography.SHA256Cng()) {
						ph_m = SHA.ComputeHash(m);
					}
#endif
					break;

				case PreHashFunction.SHA384:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
#if !NET48
					ph_m = System.Security.Cryptography.SHA384.HashData(m);
#else
					using (System.Security.Cryptography.SHA384Cng SHA = new System.Security.Cryptography.SHA384Cng()) {
						ph_m = SHA.ComputeHash(m);
					}
#endif
					break;

				case PreHashFunction.SHA512:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
#if !NET48
					ph_m = System.Security.Cryptography.SHA512.HashData(m);
#else
					using (System.Security.Cryptography.SHA512Cng SHA = new System.Security.Cryptography.SHA512Cng()) {
						ph_m = SHA.ComputeHash(m);
					}
#endif
					break;

				case PreHashFunction.SHA3_224:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07 };
					ph_m = Sha3_224.ComputeHash(m);
					break;

				case PreHashFunction.SHA3_256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08 };
					ph_m = Sha3_256.ComputeHash(m);
					break;

				case PreHashFunction.SHA3_384:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09 };
					ph_m = Sha3_384.ComputeHash(m);
					break;

				case PreHashFunction.SHA3_512:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a };
					ph_m = Sha3_512.ComputeHash(m);
					break;

				case PreHashFunction.SHAKE128:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B };
					ph_m = Shake128.HashData(m, 256);
					break;

				case PreHashFunction.SHAKE256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C };
					ph_m = Shake256.HashData(m, 512);
					break;

				default:
					throw new ArgumentException($"Invalid hash function '{ph}'");
			}

			m_prime = new byte[ctx.Length + oid.Length + ph_m.Length + 2];
			m_prime[0] = 1;
			m_prime[1] = (byte)ctx.Length;
			Array.Copy(ctx, 0, m_prime, 2, ctx.Length);
			Array.Copy(oid, 0, m_prime, ctx.Length + 2, oid.Length);
			Array.Copy(ph_m, 0, m_prime, ctx.Length + oid.Length + 2, ph_m.Length);
			return slh_sign_internal(m_prime, sk, addrnd);
		}

		/// <summary>
		/// FIPS 205 Algorithm 24 -	Verifies a pure SLH-DSA signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="sig">Signature</param>
		/// <param name="ctx">Context string</param>
		/// <param name="pk">Public key</param>
		/// <returns><c>true</c> if the signature is valid, <c>false</c> otherwise</returns>
		/// <exception cref="ArgumentException"><paramref name="ctx"/> is longer than 255 bytes</exception>
		public bool slh_verify(byte[] m, byte[] sig, byte[] ctx, byte[] pk) {
			byte[] m_prime;

			if (ctx == null) {
				ctx = Array.Empty<byte>();
			}
			if (ctx.Length > 255) {
				throw new ArgumentException("Context too long");
			}

			if (sig.Length != signature_size) {
				return false;
			}

			m_prime = new byte[ctx.Length + m.Length + 2];
			m_prime[0] = 0;
			m_prime[1] = (byte)ctx.Length;
			Array.Copy(ctx, 0, m_prime, 2, ctx.Length);
			Array.Copy(m, 0, m_prime, ctx.Length + 2, m.Length);
			return slh_verify_internal(m_prime, sig, pk);
		}

		/// <summary>
		/// FIPS 205 Algorithm 25 - Verifies a pre-hash SLH-DSA signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="sig">Signature</param>
		/// <param name="ctx">Context string</param>
		/// <param name="ph">Pre-hash function</param>
		/// <param name="pk">Public key</param>
		/// <returns><c>true</c> if the signature is valid, <c>false</c> otherwise</returns>
		/// <exception cref="ArgumentException"><paramref name="ctx"/> is longer than 255 bytes, or <paramref name="ph"/> is not supported</exception>
		public bool hash_slh_verify(byte[] m, byte[] sig, byte[] ctx, PreHashFunction ph, byte[] pk) {
			byte[] m_prime;
			byte[] ph_m;
			byte[] oid;

			if (ctx == null) {
				ctx = Array.Empty<byte>();
			}
			if (ctx.Length > 255) {
				throw new ArgumentException("Context too long");
			}

			switch (ph) {
				case PreHashFunction.SHA256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
#if !NET48
					ph_m = System.Security.Cryptography.SHA256.HashData(m);
#else
					using (System.Security.Cryptography.SHA256Cng SHA256 = new System.Security.Cryptography.SHA256Cng()) {
						ph_m = SHA256.ComputeHash(m);
					}
#endif
					break;
				case PreHashFunction.SHA512:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
#if !NET48
					ph_m = System.Security.Cryptography.SHA256.HashData(m);
#else
					using (System.Security.Cryptography.SHA512Cng SHA512 = new System.Security.Cryptography.SHA512Cng()) {
						ph_m = SHA512.ComputeHash(m);
					}
#endif
					break;
				case PreHashFunction.SHAKE128:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B };
					ph_m = Shake128.HashData(m, 256);
					break;
				case PreHashFunction.SHAKE256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C };
					ph_m = Shake256.HashData(m, 512);
					break;
				default:
					throw new ArgumentException($"Invalid hash function '{ph}'");
			}

			m_prime = new byte[ctx.Length + oid.Length + ph_m.Length + 2];
			m_prime[0] = 1;
			m_prime[1] = (byte)ctx.Length;
			Array.Copy(ctx, 0, m_prime, 2, ctx.Length);
			Array.Copy(oid, 0, m_prime, ctx.Length + 2, oid.Length);
			Array.Copy(ph_m, 0, m_prime, ctx.Length + oid.Length + 2, ph_m.Length);
			return slh_verify_internal(m_prime, sig, pk);
		}

		/// <summary>
		/// Gets an address appropriate for the chosen hash function
		/// </summary>
		/// <returns></returns>
		private IAddress GetAddress() {
			if (hash.IsShake) {
				return new ShakeAddress();
			} else {
				return new Sha2Address();
			}
		}

		/// <summary>
		/// Split the private key into its components
		/// </summary>
		/// <param name="sk">Private key</param>
		/// <param name="sk_seed">Receives the secret seed</param>
		/// <param name="sk_prf">Receives the secret key PRF</param>
		/// <param name="pk_seed">Receives the public seed</param>
		/// <param name="pk_root">Receives the HT public key</param>
		/// <exception cref="ArgumentException"></exception>
		private void SplitSk(byte[] sk, out byte[] sk_seed, out byte[] sk_prf, out byte[] pk_seed, out byte[] pk_root) {
			sk_seed = new byte[n];
			sk_prf = new byte[n];
			pk_seed = new byte[n];
			pk_root = new byte[n];

			if (sk.Length != 4 * n) {
				throw new ArgumentException("Invalid secret key size");
			}

			Array.Copy(sk, 0, sk_seed, 0, n);
			Array.Copy(sk, n, sk_prf, 0, n);
			Array.Copy(sk, 2 * n, pk_seed, 0, n);
			Array.Copy(sk, 3 * n, pk_root, 0, n);
		}

		/// <summary>
		/// Split the public key into its components
		/// </summary>
		/// <param name="pk">Public key</param>
		/// <param name="pk_seed">Receives the public seed</param>
		/// <param name="pk_root">Receives the HT public key</param>
		/// <exception cref="ArgumentException"></exception>
		private void SplitPk(byte[] pk, out byte[] pk_seed, out byte[] pk_root) {
			pk_seed = new byte[n];
			pk_root = new byte[n];

			if (pk.Length != 2 * n) {
				throw new ArgumentException("Invalid secret key size");
			}

			Array.Copy(pk, 0, pk_seed, 0, n);
			Array.Copy(pk, n, pk_root, 0, n);
		}
	}
}
