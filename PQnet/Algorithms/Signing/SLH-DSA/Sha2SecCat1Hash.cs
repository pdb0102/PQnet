﻿// MIT License
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
using System.Security.Cryptography;

namespace PQnet {
	internal class Sha2SecCat1Hash : IHashAlgorithm {
		private int n;
		private int m;

		public Sha2SecCat1Hash(int n, int m) {
			this.n = n;
			this.m = m;
		}

		public string Name {
			get {
				return "SHA2 Security Category 1";
			}
		}

		public bool IsShake {
			get {
				return false;
			}
		}

		public byte[] f(byte[] pk_seed, IAddress adrs, byte[] m_1) {
			byte[] data;
			byte[] fill;
			byte[] outbuf;

			fill = new byte[64 - n];

			data = new byte[pk_seed.Length + fill.Length + adrs.Bytes.Length + m_1.Length];
			Array.Copy(pk_seed, data, pk_seed.Length);
			Array.Copy(fill, 0, data, pk_seed.Length, fill.Length);
			Array.Copy(adrs.Bytes, 0, data, pk_seed.Length + fill.Length, adrs.Bytes.Length);
			Array.Copy(m_1, 0, data, pk_seed.Length + fill.Length + adrs.Bytes.Length, m_1.Length);

#if !NET48
			outbuf = SHA256.HashData(data);
#else
			using (SHA256Cng SHA256 = new SHA256Cng()) {
				outbuf = SHA256.ComputeHash(data);
			}
#endif
			Array.Resize(ref outbuf, n);

			return outbuf;
		}

		public byte[] h(byte[] pk_seed, IAddress adrs, byte[] m_2) {
			return f(pk_seed, adrs, m_2);
		}

		public byte[] h_msg(byte[] r, byte[] pk_seed, byte[] pk_root, byte[] m) {
			byte[] data;
			byte[] hash;

			// Calculate SHA-256 hash of r, pk_seed, pk_root, and m
			data = new byte[r.Length + pk_seed.Length + pk_root.Length + m.Length];
			Array.Copy(r, data, r.Length);
			Array.Copy(pk_seed, 0, data, r.Length, pk_seed.Length);
			Array.Copy(pk_root, 0, data, r.Length + pk_seed.Length, pk_root.Length);
			Array.Copy(m, 0, data, r.Length + pk_seed.Length + pk_root.Length, m.Length);

#if !NET48
			hash = SHA256.HashData(data);
#else
			using (SHA256Cng SHA256 = new SHA256Cng()) {
				hash = SHA256.ComputeHash(data);
			}
#endif

			// Now prepare the input for the MGF1 function
			data = new byte[r.Length + pk_seed.Length + hash.Length];
			Array.Copy(r, data, r.Length);
			Array.Copy(pk_seed, 0, data, r.Length, pk_seed.Length);
			Array.Copy(hash, 0, data, r.Length + pk_seed.Length, hash.Length);

			return mgf(data);
		}

		public byte[] prf(byte[] pk_seed, byte[] sk_seed, IAddress adrs) {
			return f(pk_seed, adrs, sk_seed);
		}

		public byte[] prf_msg(byte[] sk_prf, byte[] opt_rand, byte[] m) {
			byte[] data;
			byte[] outbuf;

			data = new byte[opt_rand.Length + m.Length];
			Array.Copy(opt_rand, 0, data, 0, opt_rand.Length);
			Array.Copy(m, 0, data, opt_rand.Length, m.Length);

#if !NET48
			outbuf = HMACSHA256.HashData(sk_prf, data);
#else
			using (HMACSHA256 hmac = new HMACSHA256(sk_prf)) {
				outbuf = hmac.ComputeHash(data);
			}
#endif
			Array.Resize(ref outbuf, n);

			return outbuf;
		}

		public byte[] t_len(byte[] pk_seed, IAddress adrs, byte[] m_l) {
			return f(pk_seed, adrs, m_l);
		}

		private byte[] mgf(byte[] mgf_seed) {
			List<byte> t;
			byte[] mgf;

			mgf = new byte[mgf_seed.Length + 4];
			Array.Copy(mgf_seed, mgf, mgf_seed.Length);

			t = new List<byte>();
#if NET48
			using (SHA256Cng SHA256 = new SHA256Cng())
#endif
			for (uint c = 0; c < (32 + m); c++) {
				Utility.toByte(c, mgf, mgf.Length - 4);
#if !NET48
				t.AddRange(SHA256.HashData(mgf));
#else
				t.AddRange(SHA256.ComputeHash(mgf));
#endif
			}
			t.RemoveRange(m, t.Count - m);
			return t.ToArray();
		}
	}
}
