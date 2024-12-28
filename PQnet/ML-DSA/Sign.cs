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

using System.Diagnostics;
using System.Security.Cryptography;

using PQnet.Digest;

namespace PQnet.ML_DSA {
	public abstract partial class MlDsaBase {
		/*************************************************
		* Name:        crypto_sign_keypair
		*
		* Description: Generates public and private key.
		*
		* Arguments:   - uint8_t *pk: pointer to output public key (allocated
		*                             array of CRYPTO_PUBLICKEYBYTES bytes)
		*              - uint8_t *sk: pointer to output private key (allocated
		*                             array of CRYPTO_SECRETKEYBYTES bytes)
		*
		* Returns 0 (success)
		**************************************************/
		public bool ml_keygen(out byte[] pk, out byte[] sk, byte[] seed = null) {
			byte[] seedbuf;
			byte[] tr;
			byte[] rho;
			byte[] rhoprime;
			byte[] key;
			PolyVecL[] mat;
			PolyVecL s1, s1hat;
			PolyVecK s2, t1, t0;

			mat = new PolyVecL[K];
			for (int i = 0; i < K; i++) {
				mat[i] = new PolyVecL(L, N);
			}

			seedbuf = new byte[(2 * SeedBytes) + CrhBytes];
			tr = new byte[TrBytes];

			/* Get randomness for rho, rhoprime and key */
			if (seed == null) {
				Rng.randombytes(out seed, SeedBytes);
			} else {
				if (seed.Length != SeedBytes) {
					pk = null;
					sk = null;
					return false;
				}
			}

			Array.Copy(seed, 0, seedbuf, 0, seed.Length);
			seedbuf[SeedBytes + 0] = (byte)K;
			seedbuf[SeedBytes + 1] = (byte)L;
			Shake.shake256(seedbuf, (2 * SeedBytes) + CrhBytes, seedbuf, SeedBytes + 2);
			rho = seedbuf;

			rhoprime = new byte[CrhBytes];
			Array.Copy(seedbuf, SeedBytes, rhoprime, 0, CrhBytes);
			key = new byte[SeedBytes];
			Array.Copy(seedbuf, SeedBytes + CrhBytes, key, 0, SeedBytes);

			/* Expand matrix */
			polyvec_matrix_expand(mat, rho);

			/* Sample short vectors s1 and s2 */
			s1 = new PolyVecL(L, N);
			s2 = new PolyVecK(K, N);
			polyvecl_uniform_eta(s1, rhoprime, 0);
			polyveck_uniform_eta(s2, rhoprime, (ushort)L);

			/* Matrix-vector multiplication */
			t0 = new PolyVecK(K, N);
			t1 = new PolyVecK(K, N);
			s1hat = s1.Clone();
			polyvecl_ntt(s1hat);
			polyvec_matrix_pointwise_montgomery(t1, mat, s1hat);
			polyveck_reduce(t1);
			polyveck_invntt_tomont(t1);

			/* Add error vector s2 */
			polyveck_add(t1, t1, s2);

			/* Extract t1 and write public key */
			polyveck_caddq(t1);
			polyveck_power2round(t1, t0, t1);
			pk = new byte[PublicKeybytes];
			pack_pk(pk, rho, t1);

			/* Compute H(rho, t1) and write secret key */
			Shake.shake256(tr, TrBytes, pk, PublicKeybytes);
			sk = new byte[SecretKeyBytes];
			pack_sk(sk, rho, tr, key, t0, s1, s2);

			return true;
		}

		/*************************************************
		* Name:        crypto_sign_signature_internal
		*
		* Description: Computes signature. Internal API.
		*
		* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
		*              - size_t *siglen: pointer to output length of signature
		*              - uint8_t *m:     pointer to message to be signed
		*              - size_t mlen:    length of message
		*              - uint8_t *pre:   pointer to prefix string
		*              - size_t prelen:  length of prefix string
		*              - uint8_t *rnd:   pointer to random seed
		*              - uint8_t *sk:    pointer to bit-packed secret key
		*
		* Returns 0 (success)
		**************************************************/
		internal int ml_sign_internal(out byte[] sig, byte[] m, byte[] pre, byte[] rnd, byte[] sk) {
			uint n;
			byte[] seedbuf;
			byte[] rho;
			byte[] tr;
			byte[] key;
			byte[] mu;
			byte[] rhoprime;
			ushort nonce = 0;
			PolyVecL[] mat;
			PolyVecL s1;
			PolyVecL y;
			PolyVecL z;
			PolyVecK t0;
			PolyVecK s2;
			PolyVecK w1;
			PolyVecK w0;
			PolyVecK h;
			Poly cp;
			Shake.keccak_state state;

			Debug.Assert(rnd.Length == RndBytes);

			cp = new Poly(N);
			mat = new PolyVecL[K];
			for (int i = 0; i < K; i++) {
				mat[i] = new PolyVecL(L, N);
			}
			s1 = new PolyVecL(L, N);
			y = new PolyVecL(L, N);
			z = new PolyVecL(L, N);
			t0 = new PolyVecK(K, N);
			s2 = new PolyVecK(K, N);
			w1 = new PolyVecK(K, N);
			w0 = new PolyVecK(K, N);
			h = new PolyVecK(K, N);

			state = new Shake.keccak_state();
			seedbuf = new byte[(2 * SeedBytes) + TrBytes + (2 * CrhBytes)];

			sig = new byte[SignatureBytes];
			rho = new byte[SeedBytes];
			tr = new byte[TrBytes];
			key = new byte[SeedBytes];
			mu = new byte[CrhBytes];
			rhoprime = new byte[CrhBytes];
			unpack_sk(rho, tr, key, t0, s1, s2, sk);

			/* Compute mu = CRH(tr, pre, msg) */
			Shake.shake256_init(state);
			Shake.shake256_absorb(state, tr, TrBytes);
			Shake.shake256_absorb(state, pre, pre.Length);
			Shake.shake256_absorb(state, m, m.Length);
			Shake.shake256_finalize(state);
			Shake.shake256_squeeze(mu, 0, CrhBytes, state);

			/* Compute rhoprime = CRH(key, rnd, mu) */
			Shake.shake256_init(state);
			Shake.shake256_absorb(state, key, SeedBytes);
			Shake.shake256_absorb(state, rnd, RndBytes);
			Shake.shake256_absorb(state, mu, CrhBytes);
			Shake.shake256_finalize(state);
			Shake.shake256_squeeze(rhoprime, 0, CrhBytes, state);

			/* Expand matrix and transform vectors */
			polyvec_matrix_expand(mat, rho);
			polyvecl_ntt(s1);
			polyveck_ntt(s2);
			polyveck_ntt(t0);

		rej:
			/* Sample intermediate vector y */
			polyvecl_uniform_gamma1(y, rhoprime, nonce++);

			/* Matrix-vector multiplication */
			z = y.Clone();
			polyvecl_ntt(z);
			polyvec_matrix_pointwise_montgomery(w1, mat, z);
			polyveck_reduce(w1);
			polyveck_invntt_tomont(w1);

			/* Decompose w and call the random oracle */
			polyveck_caddq(w1);
			polyveck_decompose(w1, w0, w1);
			polyveck_pack_w1(sig, w1);

			Shake.shake256_init(state);
			Shake.shake256_absorb(state, mu, CrhBytes);
			Shake.shake256_absorb(state, sig, K * PolyW1PackedBytes);
			Shake.shake256_finalize(state);
			Shake.shake256_squeeze(sig, 0, CTildeBytes, state);
			poly_challenge(cp, sig);
			poly_ntt(cp);

			/* Compute z, reject if it reveals secret */
			polyvecl_pointwise_poly_montgomery(z, cp, s1);
			polyvecl_invntt_tomont(z);
			polyvecl_add(z, z, y);
			polyvecl_reduce(z);
			if (polyvecl_chknorm(z, Gamma1 - Beta) != 0) {
				goto rej;
			}

			/* Check that subtracting cs2 does not change high bits of w and low bits
			 * do not reveal secret information */
			polyveck_pointwise_poly_montgomery(h, cp, s2);
			polyveck_invntt_tomont(h);
			polyveck_sub(w0, w0, h);
			polyveck_reduce(w0);
			if (polyveck_chknorm(w0, Gamma2 - Beta) != 0) {
				goto rej;
			}

			/* Compute hints for w1 */
			polyveck_pointwise_poly_montgomery(h, cp, t0);
			polyveck_invntt_tomont(h);
			polyveck_reduce(h);
			if (polyveck_chknorm(h, Gamma2) != 0) {
				goto rej;
			}

			polyveck_add(w0, w0, h);
			n = polyveck_make_hint(h, w0, w1);
			if (n > Omega) {
				goto rej;
			}

			/* Write signature */
			pack_sig(sig, sig, z, h);
			return 0;
		}

		/*************************************************
		* Name:        crypto_sign_signature
		*
		* Description: Computes signature.
		*
		* Arguments:   - uint8_t *sig:   pointer to output signature (of length CRYPTO_BYTES)
		*              - size_t *siglen: pointer to output length of signature
		*              - uint8_t *m:     pointer to message to be signed
		*              - size_t mlen:    length of message
		*              - uint8_t *ctx:   pointer to contex string
		*              - size_t ctxlen:  length of contex string
		*              - uint8_t *sk:    pointer to bit-packed secret key
		*
		* Returns 0 (success) or -1 (context string too long)
		**************************************************/
		public int ml_sign(out byte[] sig, byte[] m, byte[] ctx, byte[] sk) {
			int i;
			byte[] pre;
			byte[] rnd;

			if (ctx.Length > 255) {
				sig = null;
				return -1;
			}
			pre = new byte[ctx.Length + 2];

			/* Prepare pre = (0, ctxlen, ctx) */
			pre[0] = 0;
			pre[1] = (byte)ctx.Length;
			for (i = 0; i < ctx.Length; i++) {
				pre[2 + i] = ctx[i];
			}

			if (Deterministic) {
				Rng.randombytes(out rnd, RndBytes);
			} else {
				rnd = new byte[RndBytes];
			}

			ml_sign_internal(out sig, m, pre, rnd, sk);
			return 0;
		}

		/// <summary>
		/// FIPS 204 Algorithm 4 - Generates a pre-hash ML-DSA signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="ctx">Context string</param>
		/// <param name="ph">Pre-hash function</param>
		/// <param name="sk">Private key</param>
		/// <returns>SLH-DSA signature SIG</returns>
		/// <exception cref="ArgumentException"><paramref name="ctx"/> is longer than 255 bytes, or <paramref name="ph"/> is not supported</exception>
		public byte[] hash_ml_sign(byte[] sk, byte[] m, byte[] ctx, PreHashFunction ph) {
			byte[] addrnd;
			byte[] m_prime;
			byte[] ph_m;
			byte[] oid;
			byte[] sig;

			if (ctx == null) {
				ctx = empty_ctx;
			}
			if (ctx.Length > 255) {
				throw new ArgumentException("Context too long");
			}

			if (!Deterministic) {
				Rng.randombytes(out addrnd, SeedBytes);
			} else {
				addrnd = null_rnd;
			}

			switch (ph) {
				case PreHashFunction.SHA256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
					ph_m = SHA256.Create().ComputeHash(m);
					break;

				case PreHashFunction.SHA512:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
					ph_m = SHA512.Create().ComputeHash(m);
					break;

				case PreHashFunction.SHAKE128:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B };
					ph_m = Shake256.HashData(m, 256);
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
			ml_sign_internal(out sig, m_prime, empty_ctx, addrnd, sk);
			return sig;
		}

		/*************************************************
		* Name:        crypto_sign
		*
		* Description: Compute signed message.
		*
		* Arguments:   - uint8_t *sm: pointer to output signed message (allocated
		*                             array with CRYPTO_BYTES + mlen bytes),
		*                             can be equal to m
		*              - size_t *smlen: pointer to output length of signed
		*                               message
		*              - const uint8_t *m: pointer to message to be signed
		*              - size_t mlen: length of message
		*              - const uint8_t *ctx: pointer to context string
		*              - size_t ctxlen: length of context string
		*              - const uint8_t *sk: pointer to bit-packed secret key
		*
		* Returns 0 (success) or -1 (context string too long)
		**************************************************/
		public int ml_sign_message(out byte[] sm, byte[] m, byte[] ctx, byte[] sk) {
			int ret;
			byte[] sig;

			ret = ml_sign(out sig, m, ctx, sk);
			if (ret != 0) {
				sm = null;
				return ret;
			}
			sm = new byte[sig.Length + m.Length];
			Array.Copy(sig, 0, sm, 0, sig.Length);
			Array.Copy(m, 0, sm, sig.Length, m.Length);
			return ret;
		}


		/*************************************************
		* Name:        crypto_sign_verify_internal
		*
		* Description: Verifies signature. Internal API.
		*
		* Arguments:   - uint8_t *m: pointer to input signature
		*              - size_t siglen: length of signature
		*              - const uint8_t *m: pointer to message
		*              - size_t mlen: length of message
		*              - const uint8_t *pre: pointer to prefix string
		*              - size_t prelen: length of prefix string
		*              - const uint8_t *pk: pointer to bit-packed public key
		*
		* Returns 0 if signature could be verified correctly and -1 otherwise
		**************************************************/
		internal int ml_verify_internal(byte[] sig, byte[] m, byte[] pre, byte[] pk) {
			byte[] buf;
			byte[] rho;
			byte[] mu;
			byte[] c;
			byte[] c2;
			Poly cp;
			PolyVecL[] mat;
			PolyVecL z;
			PolyVecK t1;
			PolyVecK w1;
			PolyVecK h;
			Shake.keccak_state state;

			buf = new byte[K * PolyW1PackedBytes];
			rho = new byte[SeedBytes];
			mu = new byte[CrhBytes];
			c = new byte[CTildeBytes];
			c2 = new byte[CTildeBytes];

			cp = new Poly(N);
			mat = new PolyVecL[K];
			for (int i = 0; i < K; i++) {
				mat[i] = new PolyVecL(L, N);
			}
			z = new PolyVecL(L, N);
			t1 = new PolyVecK(K, N);
			w1 = new PolyVecK(K, N);
			h = new PolyVecK(K, N);

			state = new Shake.keccak_state();

			if (sig.Length != SignatureBytes) {
				return -1;
			}

			unpack_pk(rho, t1, pk);
			if (unpack_sig(c, z, h, sig) != 0) {
				return -1;
			}
			if (polyvecl_chknorm(z, Gamma1 - Beta) != 0) {
				return -1;
			}

			/* Compute CRH(H(rho, t1), pre, msg) */
			Shake.shake256(mu, TrBytes, pk, PublicKeybytes);
			Shake.shake256_init(state);
			Shake.shake256_absorb(state, mu, TrBytes);
			Shake.shake256_absorb(state, pre, pre.Length);
			Shake.shake256_absorb(state, m, m.Length);
			Shake.shake256_finalize(state);
			Shake.shake256_squeeze(mu, 0, CrhBytes, state);

			/* Matrix-vector multiplication; compute Az - c2^dt1 */
			poly_challenge(cp, c);
			polyvec_matrix_expand(mat, rho);

			polyvecl_ntt(z);
			polyvec_matrix_pointwise_montgomery(w1, mat, z);

			poly_ntt(cp);
			polyveck_shiftl(t1);
			polyveck_ntt(t1);
			polyveck_pointwise_poly_montgomery(t1, cp, t1);

			polyveck_sub(w1, w1, t1);
			polyveck_reduce(w1);
			polyveck_invntt_tomont(w1);

			/* Reconstruct w1 */
			polyveck_caddq(w1);
			polyveck_use_hint(w1, w1, h);
			polyveck_pack_w1(buf, w1);

			/* Call random oracle and verify challenge */
			Shake.shake256_init(state);
			Shake.shake256_absorb(state, mu, CrhBytes);
			Shake.shake256_absorb(state, buf, K * PolyW1PackedBytes);
			Shake.shake256_finalize(state);
			Shake.shake256_squeeze(c2, 0, CTildeBytes, state);
			for (int i = 0; i < CTildeBytes; i++) {
				if (c[i] != c2[i]) {
					return -1;
				}
			}

			return 0;
		}

		/*************************************************
		* Name:        crypto_sign_verify
		*
		* Description: Verifies signature.
		*
		* Arguments:   - uint8_t *m: pointer to input signature
		*              - size_t siglen: length of signature
		*              - const uint8_t *m: pointer to message
		*              - size_t mlen: length of message
		*              - const uint8_t *ctx: pointer to context string
		*              - size_t ctxlen: length of context string
		*              - const uint8_t *pk: pointer to bit-packed public key
		*
		* Returns 0 if signature could be verified correctly and -1 otherwise
		**************************************************/
		public int ml_verify(byte[] sig, byte[] m, byte[] ctx, byte[] pk) {
			int i;
			byte[] pre;

			if (ctx.Length > 255) {
				return -1;
			}
			pre = new byte[ctx.Length + 2];

			pre[0] = 0;
			pre[1] = (byte)ctx.Length;
			for (i = 0; i < ctx.Length; i++)
				pre[2 + i] = ctx[i];

			return ml_verify_internal(sig, m, pre, pk);
		}

		/// <summary>
		/// FIPS 204 Algorithm 8 - Verifies a pre-hash ML-DSA signature
		/// </summary>
		/// <param name="m">Message</param>
		/// <param name="sig">Signature</param>
		/// <param name="ctx">Context string</param>
		/// <param name="ph">Pre-hash function</param>
		/// <param name="pk">Public key</param>
		/// <returns><c>true</c> if the signature is valid, <c>false</c> otherwise</returns>
		/// <exception cref="ArgumentException"><paramref name="ctx"/> is longer than 255 bytes, or <paramref name="ph"/> is not supported</exception>
		public bool hash_ml_verify(byte[] m, byte[] sig, byte[] ctx, PreHashFunction ph, byte[] pk) {
			byte[] m_prime;
			byte[] ph_m;
			byte[] oid;

			if (ctx == null) {
				ctx = empty_ctx;
			}
			if (ctx.Length > 255) {
				throw new ArgumentException("Context too long");
			}

			switch (ph) {
				case PreHashFunction.SHA256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
					ph_m = SHA256.Create().ComputeHash(m);
					break;
				case PreHashFunction.SHA512:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
					ph_m = SHA512.Create().ComputeHash(m);
					break;
				case PreHashFunction.SHAKE128:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B };
					ph_m = Shake256.HashData(m, 256);
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
			return ml_verify_internal(sig, m_prime, Array.Empty<byte>(), pk) == 0;
		}


		/*************************************************
		* Name:        crypto_sign_open
		*
		* Description: Verify signed message.
		*
		* Arguments:   - uint8_t *m: pointer to output message (allocated
		*                            array with smlen bytes), can be equal to sm
		*              - size_t *mlen: pointer to output length of message
		*              - const uint8_t *sm: pointer to signed message
		*              - size_t smlen: length of signed message
		*              - const uint8_t *ctx: pointer to context tring
		*              - size_t ctxlen: length of context string
		*              - const uint8_t *pk: pointer to bit-packed public key
		*
		* Returns 0 if signed message could be verified correctly and -1 otherwise
		**************************************************/
		internal int ml_verify_message(out byte[] m, byte[] sm, byte[] ctx, byte[] pk) {
			byte[] sig;

			if (sm.Length < SignatureBytes) {
				goto badsig;
			}

			sig = new byte[SignatureBytes];
			Array.Copy(sm, 0, sig, 0, SignatureBytes);
			m = new byte[sm.Length - SignatureBytes];
			Array.Copy(sm, SignatureBytes, m, 0, sm.Length - SignatureBytes);

			if (ml_verify(sig, m, ctx, pk) != 0) {
				goto badsig;
			} else {
				/* All good, msg already copied, return 0 */
				return 0;
			}

		badsig:
			/* Signature verification failed */
			m = null;
			return -1;
		}
	}
}