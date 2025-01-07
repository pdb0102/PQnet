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

using PQnet.Digest;

namespace PQnet {
	public abstract partial class MlKemBase {

		/*************************************************
		* Name:        pack_pk
		*
		* Description: Serialize the public key as concatenation of the
		*              serialized vector of polynomials pk
		*              and the public seed used to generate the matrix A.
		*
		* Arguments:   uint8_t *r: pointer to the output serialized public key
		*              polyvec *pk: pointer to the input public-key polyvec
		*              const uint8_t *seed: pointer to the input public seed
		**************************************************/
		private void pack_pk(byte[] r, Polyvec pk, byte[] seed) {
			polyvec_tobytes(r, pk);
			Array.Copy(seed, 0, r, KYBER_POLYVECBYTES, KYBER_SYMBYTES);
		}

		/*************************************************
		* Name:        unpack_pk
		*
		* Description: De-serialize public key from a byte array;
		*              approximate inverse of pack_pk
		*
		* Arguments:   - polyvec *pk: pointer to output public-key polynomial vector
		*              - uint8_t *seed: pointer to output seed to generate matrix A
		*              - const uint8_t *packedpk: pointer to input serialized public key
		**************************************************/
		private void unpack_pk(Polyvec pk, byte[] seed, byte[] packedpk) {
			polyvec_frombytes(pk, packedpk);
			Array.Copy(packedpk, KYBER_POLYVECBYTES, seed, 0, KYBER_SYMBYTES);
		}

		/*************************************************
		* Name:        pack_sk
		*
		* Description: Serialize the secret key
		*
		* Arguments:   - uint8_t *r: pointer to output serialized secret key
		*              - polyvec *sk: pointer to input vector of polynomials (secret key)
		**************************************************/
		private void pack_sk(byte[] r, Polyvec sk) {
			polyvec_tobytes(r, sk);
		}

		/*************************************************
		* Name:        unpack_sk
		*
		* Description: De-serialize the secret key; inverse of pack_sk
		*
		* Arguments:   - polyvec *sk: pointer to output vector of polynomials (secret key)
		*              - const uint8_t *packedsk: pointer to input serialized secret key
		**************************************************/
		private void unpack_sk(Polyvec sk, byte[] packedsk) {
			polyvec_frombytes(sk, packedsk);
		}

		/*************************************************
		* Name:        pack_ciphertext
		*
		* Description: Serialize the ciphertext as concatenation of the
		*              compressed and serialized vector of polynomials b
		*              and the compressed and serialized polynomial v
		*
		* Arguments:   uint8_t *r: pointer to the output serialized ciphertext
		*              poly *pk: pointer to the input vector of polynomials b
		*              poly *v: pointer to the input polynomial v
		**************************************************/
		private void pack_ciphertext(byte[] r, Polyvec b, Poly v) {
			polyvec_compress(r, b);
			poly_compress(r, KYBER_POLYVECCOMPRESSEDBYTES, v);
		}

		/*************************************************
		* Name:        unpack_ciphertext
		*
		* Description: De-serialize and decompress ciphertext from a byte array;
		*              approximate inverse of pack_ciphertext
		*
		* Arguments:   - polyvec *b: pointer to the output vector of polynomials b
		*              - poly *v: pointer to the output polynomial v
		*              - const uint8_t *c: pointer to the input serialized ciphertext
		**************************************************/
		private void unpack_ciphertext(Polyvec b, Poly v, byte[] c) {
			polyvec_decompress(b, c);
			poly_decompress(v, c, KYBER_POLYVECCOMPRESSEDBYTES);
		}

		/*************************************************
		* Name:        rej_uniform
		*
		* Description: Run rejection sampling on uniform random bytes to generate
		*              uniform random integers mod q
		*
		* Arguments:   - int16_t *r: pointer to output buffer
		*              - unsigned int len: requested number of 16-bit integers (uniform mod q)
		*              - const uint8_t *buf: pointer to input buffer (assumed to be uniformly random bytes)
		*              - unsigned int buflen: length of input buffer in bytes
		*
		* Returns number of sampled 16-bit integers (at most len)
		**************************************************/
		private uint rej_uniform(short[] r, int r_offset, int len, byte[] buf, int buflen) {
			uint ctr, pos;
			ushort val0, val1;

			ctr = pos = 0;
			while (ctr < len && pos + 3 <= buflen) {
				val0 = (ushort)(((buf[pos + 0] >> 0) | (buf[pos + 1] << 8)) & 0xFFF);
				val1 = (ushort)(((buf[pos + 1] >> 4) | (buf[pos + 2] << 4)) & 0xFFF);
				pos += 3;

				if (val0 < KYBER_Q) {
					r[r_offset + ctr++] = (short)val0;
				}
				if (ctr < len && val1 < KYBER_Q) {
					r[r_offset + ctr++] = (short)val1;
				}
			}

			return ctr;
		}

		//#define gen_a(A,B)  gen_matrix(A,B,0)
		//#define gen_at(A,B) gen_matrix(A,B,1)

		/*************************************************
		* Name:        gen_matrix
		*
		* Description: Deterministically generate matrix A (or the transpose of A)
		*              from a seed. Entries of the matrix are polynomials that look
		*              uniformly random. Performs rejection sampling on output of
		*              a XOF
		*
		* Arguments:   - polyvec *a: pointer to ouptput matrix A
		*              - const uint8_t *seed: pointer to input seed
		*              - int transposed: boolean deciding whether A or A^T is generated
		**************************************************/

		//#define GEN_MATRIX_NBLOCKS ((12*KYBER_N/8*(1 << 12)/KYBER_Q + XOF_BLOCKBYTES)/XOF_BLOCKBYTES)
		// Not static for benchmarking
		private void gen_matrix(Polyvec[] a, byte[] seed, bool transposed) {
			uint ctr;
			int buflen;
			byte[] buf;
			Shake128 shake128;
			int GEN_MATRIX_NBLOCKS;

			shake128 = new Shake128();

			GEN_MATRIX_NBLOCKS = ((12 * KYBER_N / 8 * (1 << 12) / KYBER_Q) + Shake128.Shake128Rate) / Shake128.Shake128Rate;

			buf = new byte[GEN_MATRIX_NBLOCKS * Shake128.Shake128Rate];

			for (int i = 0; i < KYBER_K; i++) {
				for (int j = 0; j < KYBER_K; j++) {
					if (transposed) {
						kyber_shake128_absorb(shake128, seed, (byte)i, (byte)j); //xof_absorb(&state, seed, i, j);
					} else {
						kyber_shake128_absorb(shake128, seed, (byte)j, (byte)i); // xof_absorb(&state, seed, j, i);
					}

					shake128.SqueezeBlocks(buf, 0, GEN_MATRIX_NBLOCKS); // xof_squeezeblocks(buf, GEN_MATRIX_NBLOCKS, &state);
					buflen = GEN_MATRIX_NBLOCKS * Shake128.Shake128Rate;
					ctr = rej_uniform(a[i].vec[j].coeffs, 0, KYBER_N, buf, buflen);

					while (ctr < KYBER_N) {
						shake128.SqueezeBlocks(buf, 0, 1); //xof_squeezeblocks(buf, 1, &state);
						buflen = Shake128.Shake128Rate;
						ctr += rej_uniform(a[i].vec[j].coeffs, (int)ctr, (int)(KYBER_N - ctr), buf, buflen);
					}
				}
			}
		}

		/*************************************************
		* Name:        indcpa_keypair_derand
		*
		* Description: Generates public and private key for the CPA-secure
		*              public-key encryption scheme underlying Kyber
		*
		* Arguments:   - uint8_t *pk: pointer to output public key
		*                             (of length KYBER_INDCPA_PUBLICKEYBYTES bytes)
		*              - uint8_t *sk: pointer to output private key
		*                             (of length KYBER_INDCPA_SECRETKEYBYTES bytes)
		*              - const uint8_t *coins: pointer to input randomness
		*                             (of length KYBER_SYMBYTES bytes)
		**************************************************/
		private void indcpa_keypair_derand(byte[] pk, byte[] sk, byte[] coins) {
			int i;
			byte[] buf;
			byte[] publicseed;
			byte[] noiseseed;
			byte nonce;
			Polyvec[] a;
			Polyvec e;
			Polyvec pkpv;
			Polyvec skpv;

			nonce = 0;

			a = new Polyvec[KYBER_K];
			for (i = 0; i < a.Length; i++) {
				a[i] = new Polyvec(KYBER_K, KYBER_N);
			}
			e = new Polyvec(KYBER_K, KYBER_N);
			pkpv = new Polyvec(KYBER_K, KYBER_N);
			skpv = new Polyvec(KYBER_K, KYBER_N);

			buf = new byte[2 * KYBER_SYMBYTES];
			Array.Copy(coins, buf, KYBER_SYMBYTES);

			buf[KYBER_SYMBYTES] = (byte)KYBER_K;
			buf = Sha3_512.ComputeHash(buf, KYBER_SYMBYTES + 1);

			publicseed = new byte[KYBER_SYMBYTES];
			Array.Copy(buf, publicseed, KYBER_SYMBYTES);
			noiseseed = new byte[KYBER_SYMBYTES];
			Array.Copy(buf, KYBER_SYMBYTES, noiseseed, 0, KYBER_SYMBYTES);


			gen_matrix(a, publicseed, false);   // gen_a(a, publicseed);

			for (i = 0; i < KYBER_K; i++) {
				poly_getnoise_eta1(skpv.vec[i], noiseseed, nonce++);
			}
			for (i = 0; i < KYBER_K; i++) {
				poly_getnoise_eta1(e.vec[i], noiseseed, nonce++);
			}

			polyvec_ntt(skpv);
			polyvec_ntt(e);

			// matrix-vector multiplication
			for (i = 0; i < KYBER_K; i++) {
				polyvec_basemul_acc_montgomery(pkpv.vec[i], a[i], skpv);
				poly_tomont(pkpv.vec[i]);
			}

			polyvec_add(pkpv, pkpv, e);
			polyvec_reduce(pkpv);

			pack_sk(sk, skpv);
			pack_pk(pk, pkpv, publicseed);
		}


		/*************************************************
		* Name:        indcpa_enc
		*
		* Description: Encryption function of the CPA-secure
		*              public-key encryption scheme underlying Kyber.
		*
		* Arguments:   - uint8_t *c: pointer to output ciphertext
		*                            (of length KYBER_INDCPA_BYTES bytes)
		*              - const uint8_t *m: pointer to input message
		*                                  (of length KYBER_INDCPA_MSGBYTES bytes)
		*              - const uint8_t *pk: pointer to input public key
		*                                   (of length KYBER_INDCPA_PUBLICKEYBYTES)
		*              - const uint8_t *coins: pointer to input random coins used as seed
		*                                      (of length KYBER_SYMBYTES) to deterministically
		*                                      generate all randomness
		**************************************************/
		private void indcpa_enc(byte[] c, byte[] m, Span<byte> pk, Span<byte> coins) {
			byte[] seed;
			byte nonce;
			Polyvec sp;
			Polyvec pkpv;
			Polyvec ep;
			Polyvec[] at;
			Polyvec b;
			Poly v;
			Poly k;
			Poly epp;

			nonce = 0;
			seed = new byte[KYBER_SYMBYTES];

			sp = new Polyvec(KYBER_K, KYBER_N);
			pkpv = new Polyvec(KYBER_K, KYBER_N);
			ep = new Polyvec(KYBER_K, KYBER_N);
			b = new Polyvec(KYBER_K, KYBER_N);
			at = new Polyvec[KYBER_K];
			for (int i = 0; i < at.Length; i++) {
				at[i] = new Polyvec(KYBER_K, KYBER_N);
			}
			v = new Poly(KYBER_N);
			k = new Poly(KYBER_N);
			epp = new Poly(KYBER_N);

			unpack_pk(pkpv, seed, pk.ToArray());
			poly_frommsg(k, m);
			gen_matrix(at, seed, true);    // gen_at(at, seed);

			for (int i = 0; i < KYBER_K; i++) {
				poly_getnoise_eta1(sp.vec[i], coins, nonce++);
			}
			for (int i = 0; i < KYBER_K; i++) {
				poly_getnoise_eta2(ep.vec[i], coins, nonce++);
			}
			poly_getnoise_eta2(epp, coins, nonce++);

			polyvec_ntt(sp);

			// matrix-vector multiplication
			for (int i = 0; i < KYBER_K; i++) {
				polyvec_basemul_acc_montgomery(b.vec[i], at[i], sp);
			}

			polyvec_basemul_acc_montgomery(v, pkpv, sp);

			polyvec_invntt_tomont(b);
			poly_invntt_tomont(v);

			polyvec_add(b, b, ep);
			poly_add(v, v, epp);
			poly_add(v, v, k);
			polyvec_reduce(b);
			poly_reduce(v);

			pack_ciphertext(c, b, v);
		}

		/*************************************************
		* Name:        indcpa_dec
		*
		* Description: Decryption function of the CPA-secure
		*              public-key encryption scheme underlying Kyber.
		*
		* Arguments:   - uint8_t *m: pointer to output decrypted message
		*                            (of length KYBER_INDCPA_MSGBYTES)
		*              - const uint8_t *c: pointer to input ciphertext
		*                                  (of length KYBER_INDCPA_BYTES)
		*              - const uint8_t *sk: pointer to input secret key
		*                                   (of length KYBER_INDCPA_SECRETKEYBYTES)
		**************************************************/
		private void indcpa_dec(byte[] m, byte[] c, byte[] sk) {
			Polyvec b;
			Polyvec skpv;
			Poly v;
			Poly mp;

			b = new Polyvec(KYBER_K, KYBER_N);
			skpv = new Polyvec(KYBER_K, KYBER_N);
			v = new Poly(KYBER_N);
			mp = new Poly(KYBER_N);

			unpack_ciphertext(b, v, c);
			unpack_sk(skpv, sk);

			polyvec_ntt(b);
			polyvec_basemul_acc_montgomery(mp, skpv, b);
			poly_invntt_tomont(mp);

			poly_sub(mp, v, mp);
			poly_reduce(mp);

			poly_tomsg(m, mp);
		}
	}
}