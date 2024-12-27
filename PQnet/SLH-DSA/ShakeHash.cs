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

using PQnet.Digest;

namespace PQnet.SLH_DSA {
	/// <summary>
	/// FIPS 205 Section 11.1 SHAKE
	/// </summary>
	internal class ShakeHash : IHashAlgorithm {
		int m;
		int n;

		public ShakeHash(int n, int m) {
			this.m = m;
			this.n = n;
		}

		public string Name {
			get {
				return "Shake";
			}
		}

		public bool IsShake {
			get {
				return true;
			}
		}

		/// <summary>
		/// SHAKE256(PK.seed ∥ ADRS ∥ 𝑀1, 8𝑛)
		/// </summary>
		/// <param name="pk_seed"></param>
		/// <param name="adrs"></param>
		/// <param name="m_1"></param>
		/// <returns></returns>
		public byte[] f(byte[] pk_seed, IAddress adrs, byte[] m_1) {
			byte[] data;

			data = new byte[pk_seed.Length + adrs.Bytes.Length + m_1.Length];
			Array.Copy(pk_seed, data, pk_seed.Length);
			Array.Copy(adrs.Bytes, 0, data, pk_seed.Length, adrs.Bytes.Length);
			Array.Copy(m_1, 0, data, pk_seed.Length + adrs.Bytes.Length, m_1.Length);

			if (Shake256.IsSupported) {
				return Shake256.HashData(data, n);
			} else {
				byte[] outbuf;

				outbuf = new byte[n];
				Shake.shake256(outbuf, n, data, data.Length);
				return outbuf;
			}
		}

		/// <summary>
		/// SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)
		/// </summary>
		/// <param name="pk_seed"></param>
		/// <param name="adrs"></param>
		/// <param name="m_2"></param>
		/// <returns></returns>
		public byte[] h(byte[] pk_seed, IAddress adrs, byte[] m_2) {
			return f(pk_seed, adrs, m_2);
		}

		/// <summary>
		/// SHAKE256(𝑅 ∥ PK.seed ∥ PK.root ∥ 𝑀 , 8𝑚)
		/// </summary>
		/// <param name="r"></param>
		/// <param name="pk_seed"></param>
		/// <param name="pk_root"></param>
		/// <param name="m"></param>
		/// <returns></returns>
		public byte[] h_msg(byte[] r, byte[] pk_seed, byte[] pk_root, byte[] m) {
			byte[] data;

			data = new byte[r.Length + pk_seed.Length + pk_root.Length + m.Length];
			Array.Copy(r, data, r.Length);
			Array.Copy(pk_seed, 0, data, r.Length, pk_seed.Length);
			Array.Copy(pk_root, 0, data, r.Length + pk_seed.Length, pk_root.Length);
			Array.Copy(m, 0, data, r.Length + pk_seed.Length + pk_root.Length, m.Length);

			if (Shake256.IsSupported) {
				return Shake256.HashData(data, this.m);
			} else {
				byte[] outbuf;

				outbuf = new byte[this.m];
				Shake.shake256(outbuf, this.m, data, data.Length);
				return outbuf;
			}
		}

		/// <summary>
		/// SHAKE256(PK.seed ∥ ADRS ∥ SK.seed, 8𝑛)
		/// </summary>
		/// <param name="pk_seed"></param>
		/// <param name="sk_seed"></param>
		/// <param name="adrs"></param>
		/// <returns></returns>
		public byte[] prf(byte[] pk_seed, byte[] sk_seed, IAddress adrs) {
			byte[] data;

			data = new byte[pk_seed.Length + sk_seed.Length + adrs.Bytes.Length];
			Array.Copy(pk_seed, data, pk_seed.Length);
			Array.Copy(adrs.Bytes, 0, data, pk_seed.Length, adrs.Bytes.Length);
			Array.Copy(sk_seed, 0, data, pk_seed.Length + adrs.Bytes.Length, sk_seed.Length);

			if (Shake256.IsSupported) {
				return Shake256.HashData(data, this.n);
			} else {
				byte[] outbuf;

				outbuf = new byte[n];
				Shake.shake256(outbuf, n, data, data.Length);
				return outbuf;
			}
		}

		/// <summary>
		/// SHAKE256(SK.prf ∥ 𝑜𝑝𝑡_𝑟𝑎𝑛𝑑 ∥ 𝑀 , 8𝑛)
		/// </summary>
		/// <param name="sk_prf"></param>
		/// <param name="opt_rand"></param>
		/// <param name="m"></param>
		/// <returns></returns>
		public byte[] prf_msg(byte[] sk_prf, byte[] opt_rand, byte[] m) {
			byte[] data;

			data = new byte[sk_prf.Length + opt_rand.Length + m.Length];
			Array.Copy(sk_prf, data, sk_prf.Length);
			Array.Copy(opt_rand, 0, data, sk_prf.Length, opt_rand.Length);
			Array.Copy(m, 0, data, sk_prf.Length + opt_rand.Length, m.Length);
			if (Shake256.IsSupported) {
				return Shake256.HashData(data, this.n);
			} else {
				byte[] outbuf;

				outbuf = new byte[n];
				Shake.shake256(outbuf, n, data, data.Length);
				return outbuf;
			}
		}

		/// <summary>
		/// SHAKE256(PK.seed ∥ ADRS ∥ 𝑀2, 8𝑛)
		/// </summary>
		/// <param name="pk_seed"></param>
		/// <param name="adrs"></param>
		/// <param name="m_l"></param>
		/// <returns></returns>
		public byte[] t_len(byte[] pk_seed, IAddress adrs, byte[] m_l) {
			return f(pk_seed, adrs, m_l);
		}
	}
}