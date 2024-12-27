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

using System.Runtime.CompilerServices;
using System.Security.Cryptography;

namespace slhdsa;
public abstract partial class SlhDsaBase {
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

	private int private_key_size;
	private int public_key_size;
	private int signature_size;

	private string name;

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
		len2 = ((int)Math.Log2(len1 * (w - 1)) / lg_w) + 1;
		len = len1 + len2;

		private_key_size = 2 * n;
		public_key_size = 4 * n;
		signature_size = (1 + (k * (1 + a)) + h + (d * len)) * n;

		name = $"SLH-DSA-{hash.Name}-{8 * n}f";
	}

	public bool Deterministic { get; set; }

	/// <summary>
	/// Gets an address appropriate for the chosen hash function
	/// </summary>
	/// <returns></returns>
	private IAddress GetAddress() {
		if (hash.is_shake) {
			return new ShakeAddress();
		} else {
			return new Sha2Address();
		}
	}

	/// <summary>
	/// FIPS 205 Algorithm 2 
	/// </summary>
	/// <param name="b"></param>
	/// <param name="offset"></param>
	/// <param name="i"></param>
	[MethodImpl(MethodImplOptions.AggressiveInlining)]
	public static long toInt(byte[] x, int n) {
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
	public static byte[] toByte(long x, int n) {
		byte[] b;

		b = new byte[n];
		for (int i = 0; i < n; i++) {
			b[i] = (byte)(x >> (8 * (n - 1 - i)));
		}

		return b;
	}

	// FIPS 205 - Algorithm 4
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

	// FIPS 205 - Algorithm 5
	private byte[] chain(byte[] x, int i, int s, byte[] pk_seed, IAddress adrs) {
		byte[] tmp;

		tmp = x;

		for (int j = i; j < i + s; j++) {
			adrs.SetHashAddress((uint)j);
			tmp = hash.f(pk_seed, adrs, tmp);
		}

		return tmp;
	}

	// FIPS 205 - Algorithm 6
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

	// FIPS 205 - Algorithm 7
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

	// FIPS 205 - Algorithm 8
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

	// FIPS 205 - Algorithm 9
	private byte[] xmss_node(byte[] sk_seed, long i, long z, byte[] pk_seed, IAddress adrs) {
		if (z == 0) {
			adrs.SetTypeAndClear(AddressType.WotsHash);
			adrs.SetKeyPairAddress((uint)i);
			return wots_pkGen(sk_seed, pk_seed, adrs);
		} else {
			byte[] lnode;
			byte[] rnode;

			lnode = xmss_node(sk_seed, 2 * i, z - 1, pk_seed, adrs);
			rnode = xmss_node(sk_seed, (2 * i) + 1, z - 1, pk_seed, adrs);
			adrs.SetTypeAndClear(AddressType.Tree);
			adrs.SetTreeHeight((uint)z);
			adrs.SetTreeIndex((uint)i);
			return hash.h(pk_seed, adrs, lnode.Concat(rnode).ToArray());
		}
	}

	// FIPS 205 - Algorithm 10
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

	// FIPS 205 - Algorithm 11
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

	// FIPS 205 - Algorithm 12
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
			idx_tree >>= h_prime;
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

	// FIPS 205 - Algorithm 13
	private bool ht_verify(byte[] m, byte[] sig_ht, byte[] pk_seed, int idx_tree, int idx_leaf, byte[] pk_root) {
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
		for (int j = 1; j < (d - 1); j++) {
			idx_leaf = idx_tree & mask;
			idx_tree >>= h_prime;
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

	// FIPS 205 - Algorithm 14
	private byte[] fors_skGen(byte[] sk_seed, byte[] pk_seed, IAddress adrs, int idx) {
		IAddress sk_adrs;

		sk_adrs = adrs.Clone();
		sk_adrs.SetTypeAndClear(AddressType.ForsPrf);
		sk_adrs.SetKeyPairAddress(adrs.KeyPairAddress);
		sk_adrs.SetTreeIndex((uint)idx);
		return hash.prf(pk_seed, sk_seed, sk_adrs);
	}

	// FIPS 205 - Algorithm 15
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

	// FIPS 205 - Algorithm 16
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

	// FIPS 205 - Algorithm 17
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

	// FIPS 205 - Algorithm 18
	public (byte[], byte[]) slh_keygen_internal(byte[] sk_seed, byte[] sk_prf, byte[] pk_seed) {
		IAddress adrs;
		byte[] pk_root;

		adrs = GetAddress();
		adrs.SetLayerAddress((uint)d - 1);
		pk_root = xmss_node(sk_seed, 0, h_prime, pk_seed, adrs);


		return (sk_seed.Concat(sk_prf).Concat(pk_seed).Concat(pk_root).ToArray(), pk_seed.Concat(pk_root).ToArray());
	}


	// FIPS 205 - Algorithm 19
	public byte[] slh_sign_internal(byte[] m, byte[] sk, byte[] addrnd) {
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

		idx_tree = toInt(tmp_idx_tree, (h_hd + 7) / 8) % ((long)1 << h_hd);
		idx_leaf = toInt(tmp_idx_leaf, (hd + 7) / 8) % ((long)1 << hd);

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

	// FIPS 205 - Algorithm 20
	public bool slh_verify_internal(byte[] m, byte[] sig, byte[] pk) {
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

		sig_fors = new byte[(1 + (k * (1 + a))) * (n - 1)];
		Array.Copy(sig_fors, n, sig_fors, 0, sig_fors.Length);
		sig_ht = new byte[sig.Length - sig_fors.Length - r.Length];
		Array.Copy(sig, sig_fors.Length + r.Length, sig_ht, 0, sig_ht.Length);

		digest = hash.h_msg(r, pk_seed, pk_root, m);
		md = GetDigestPart(0, ka);
		tmp_idx_tree = GetDigestPart(ka, (h_hd + 7) / 8);
		tmp_idx_leaf = GetDigestPart(ka + ((h_hd + 7) / 8), (hd + 7) / 8);

		idx_tree = toInt(tmp_idx_tree, (h_hd + 7) / 8 % (1 << h_hd));
		idx_leaf = toInt(tmp_idx_leaf, (hd + 7) / 8 % (1 << hd));

		adrs.SetTreeAddress((ulong)idx_tree);
		adrs.SetTypeAndClear(AddressType.ForsTree);
		adrs.SetKeyPairAddress((uint)idx_leaf);

		pk_fors = fors_pkFromSig(sig_fors, md, pk_seed, adrs);
		return ht_verify(pk_fors, sig_ht, pk_seed, (int)idx_tree, (int)idx_leaf, pk_root);
	}

	// FIPS 205 - Algorithm 21
	public void slh_keygen(out byte[] sk, out byte[] pk) {
		byte[] sk_seed;
		byte[] sk_prf;
		byte[] pk_seed;

		randombytes(out sk_seed, n);
		randombytes(out sk_prf, n);
		randombytes(out pk_seed, n);

		(sk, pk) = slh_keygen_internal(sk_seed, sk_prf, pk_seed);
	}

	// FIPS 205 - Algorithm 22
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
			randombytes(out addrnd, n);
		} else {
			addrnd = null;
		}

		m_prime = new byte[m.Length + ctx.Length + 2];
		m_prime[0] = 1;
		m_prime[1] = (byte)ctx.Length;
		Array.Copy(ctx, 0, m_prime, 2, ctx.Length);
		Array.Copy(m, 0, m_prime, ctx.Length + 2, m.Length);

		return slh_sign_internal(m_prime, sk, addrnd);
	}

	// FIPS 205 - Algorithm 23
	public byte[] hash_slh_sign(byte[] m, byte[] ctx, string ph, byte[] sk) {
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
			randombytes(out addrnd, n);
		} else {
			addrnd = null;
		}

		switch (ph) {
			case "SHA256":
				oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
				ph_m = SHA256.Create().ComputeHash(m);
				break;

			case "SHA512":
				oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
				ph_m = SHA512.Create().ComputeHash(m);
				break;

			case "SHAKE128":
				oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B };
				ph_m = Shake256.HashData(m, 256);
				break;

			case "SHAKE256":
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

	// FIPS 205 - Algorithm 24
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
		m_prime[0] = 1;
		m_prime[1] = (byte)ctx.Length;
		Array.Copy(ctx, 0, m_prime, 2, ctx.Length);
		Array.Copy(m, 0, m_prime, ctx.Length + 2, m.Length);
		return slh_verify_internal(m_prime, sig, pk);
	}

	// FIPS 205 - Algorithm 25
	public bool hash_slh_verify(byte[] m, byte[] sig, byte[] ctx, string ph, byte[] pk) {
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
			case "SHA256":
				oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
				ph_m = SHA256.Create().ComputeHash(m);
				break;
			case "SHA512":
				oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
				ph_m = SHA512.Create().ComputeHash(m);
				break;
			case "SHAKE128":
				oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B };
				ph_m = Shake256.HashData(m, 256);
				break;
			case "SHAKE256":
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

	private void randombytes(out byte[] out_buffer, int outlen) {
		out_buffer = RandomNumberGenerator.GetBytes(outlen);
	}

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

	private void SplitPk(byte[] pk, out byte[] pk_seed, out byte[] pk_root) {
		pk_seed = new byte[n];
		pk_root = new byte[n];

		if (pk.Length != 2 * n) {
			throw new ArgumentException("Invalid secret key size");
		}

		Array.Copy(pk, 0, pk_seed, 0, n);
		Array.Copy(pk, n, pk_root, 0, n);
	}

	public virtual string Name {
		get {
			return name;
		}
	}
}
