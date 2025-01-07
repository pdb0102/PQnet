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

namespace PQnet {
	public abstract partial class MlKemBase {

		/*************************************************
		* Name:        poly_compress
		*
		* Description: Compression and subsequent serialization of a polynomial
		*
		* Arguments:   - uint8_t *r: pointer to output byte array
		*                            (of length KYBER_POLYCOMPRESSEDBYTES)
		*              - const poly *a: pointer to input polynomial
		**************************************************/

		private class Poly {
			public Poly(int n) {
				coeffs = new short[n];
			}
			public short[] coeffs;
		}

		private void poly_compress(byte[] r, int r_offset, Poly a) {
			int u;
			uint d0;
			byte[] t;

			t = new byte[8];

			if (KYBER_POLYCOMPRESSEDBYTES == 128) {

				for (int i = 0; i < KYBER_N / 8; i++) {
					for (int j = 0; j < 8; j++) {
						// map to positive standard representatives
						u = a.coeffs[(8 * i) + j];
						u += (u >> 15) & KYBER_Q;
						// t[j] = ((((uint16_t)u << 4) + KYBER_Q/2)/KYBER_Q) & 15;
						d0 = (uint)u << 4;
						d0 += 1665;
						d0 *= 80635;
						d0 >>= 28;
						t[j] = (byte)(d0 & 0xf);
					}

					r[r_offset + 0] = (byte)(t[0] | (t[1] << 4));
					r[r_offset + 1] = (byte)(t[2] | (t[3] << 4));
					r[r_offset + 2] = (byte)(t[4] | (t[5] << 4));
					r[r_offset + 3] = (byte)(t[6] | (t[7] << 4));
					r_offset += 4;
				}
			} else if (KYBER_POLYCOMPRESSEDBYTES == 160) {
				for (int i = 0; i < KYBER_N / 8; i++) {
					for (int j = 0; j < 8; j++) {
						// map to positive standard representatives
						u = a.coeffs[(8 * i) + j];
						u += (u >> 15) & KYBER_Q;
						// t[j] = ((((uint32_t)u << 5) + KYBER_Q/2)/KYBER_Q) & 31;
						d0 = (uint)(u << 5);
						d0 += 1664;
						d0 *= 40318;
						d0 >>= 27;
						t[j] = (byte)(d0 & 0x1f);
					}

					r[r_offset + 0] = (byte)((t[0] >> 0) | (t[1] << 5));
					r[r_offset + 1] = (byte)((t[1] >> 3) | (t[2] << 2) | (t[3] << 7));
					r[r_offset + 2] = (byte)((t[3] >> 1) | (t[4] << 4));
					r[r_offset + 3] = (byte)((t[4] >> 4) | (t[5] << 1) | (t[6] << 6));
					r[r_offset + 4] = (byte)((t[6] >> 2) | (t[7] << 3));
					r_offset += 5;
				}
			} else {
				throw new Exception("KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}");
			}
		}

		/*************************************************
		* Name:        poly_decompress
		*
		* Description: De-serialization and subsequent decompression of a polynomial;
		*              approximate inverse of poly_compress
		*
		* Arguments:   - poly *r: pointer to output polynomial
		*              - const uint8_t *a: pointer to input byte array
		*                                  (of length KYBER_POLYCOMPRESSEDBYTES bytes)
		**************************************************/
		private void poly_decompress(Poly r, byte[] a, int a_offset) {
			if (KYBER_POLYCOMPRESSEDBYTES == 128) {
				for (int i = 0; i < KYBER_N / 2; i++) {
					r.coeffs[(2 * i) + 0] = (short)((((ushort)(a[a_offset + 0] & 15) * KYBER_Q) + 8) >> 4);
					r.coeffs[(2 * i) + 1] = (short)((((ushort)(a[a_offset + 0] >> 4) * KYBER_Q) + 8) >> 4);
					a_offset += 1;
				}
			} else if (KYBER_POLYCOMPRESSEDBYTES == 160) {
				byte[] t;

				t = new byte[8];

				for (int i = 0; i < KYBER_N / 8; i++) {
					t[0] = (byte)(a[a_offset + 0] >> 0);
					t[1] = (byte)((a[a_offset + 0] >> 5) | (a[a_offset + 1] << 3));
					t[2] = (byte)(a[a_offset + 1] >> 2);
					t[3] = (byte)((a[a_offset + 1] >> 7) | (a[a_offset + 2] << 1));
					t[4] = (byte)((a[a_offset + 2] >> 4) | (a[a_offset + 3] << 4));
					t[5] = (byte)(a[a_offset + 3] >> 1);
					t[6] = (byte)((a[a_offset + 3] >> 6) | (a[a_offset + 4] << 2));
					t[7] = (byte)(a[a_offset + 4] >> 3);
					a_offset += 5;

					for (int j = 0; j < 8; j++) {
						r.coeffs[(8 * i) + j] = (short)((((uint)(t[j] & 31) * KYBER_Q) + 16) >> 5);
					}
				}
			} else {
				throw new Exception("KYBER_POLYCOMPRESSEDBYTES needs to be in {128, 160}");
			}
		}

		/*************************************************
		* Name:        poly_tobytes
		*
		* Description: Serialization of a polynomial
		*
		* Arguments:   - uint8_t *r: pointer to output byte array
		*                            (needs space for KYBER_POLYBYTES bytes)
		*              - const poly *a: pointer to input polynomial
		**************************************************/
		private void poly_tobytes(byte[] r, int r_offset, Poly a) {
			ushort t0, t1;

			for (int i = 0; i < KYBER_N / 2; i++) {
				// map to positive standard representatives
				t0 = (ushort)a.coeffs[2 * i];
				t0 += (ushort)(((short)t0 >> 15) & KYBER_Q);
				t1 = (ushort)a.coeffs[(2 * i) + 1];
				t1 += (ushort)(((short)t1 >> 15) & KYBER_Q);
				r[r_offset + (3 * i) + 0] = (byte)(t0 >> 0);
				r[r_offset + (3 * i) + 1] = (byte)((t0 >> 8) | (t1 << 4));
				r[r_offset + (3 * i) + 2] = (byte)(t1 >> 4);
			}
		}

		/*************************************************
		* Name:        poly_frombytes
		*
		* Description: De-serialization of a polynomial;
		*              inverse of poly_tobytes
		*
		* Arguments:   - poly *r: pointer to output polynomial
		*              - const uint8_t *a: pointer to input byte array
		*                                  (of KYBER_POLYBYTES bytes)
		**************************************************/
		private void poly_frombytes(Poly r, byte[] a, int a_offset) {
			for (int i = 0; i < KYBER_N / 2; i++) {
				r.coeffs[2 * i] = (short)(((a[a_offset + (3 * i) + 0] >> 0) | (a[a_offset + (3 * i) + 1] << 8)) & 0xFFF);
				r.coeffs[(2 * i) + 1] = (short)(((a[a_offset + (3 * i) + 1] >> 4) | (a[a_offset + (3 * i) + 2] << 4)) & 0xFFF);
			}
		}

		/*************************************************
		* Name:        poly_frommsg
		*
		* Description: Convert 32-byte message to polynomial
		*
		* Arguments:   - poly *r: pointer to output polynomial
		*              - const uint8_t *msg: pointer to input message
		**************************************************/
		private void poly_frommsg(Poly r, byte[] msg) {
#if DEBUG
			if (KYBER_INDCPA_MSGBYTES != KYBER_N / 8) {
				throw new Exception("KYBER_INDCPA_MSGBYTES must be equal to KYBER_N/8 bytes!");
			}
#endif

			for (int i = 0; i < KYBER_N / 8; i++) {
				for (int j = 0; j < 8; j++) {
					r.coeffs[(8 * i) + j] = 0;
					cmov_int16(ref r.coeffs[(8 * i) + j], (short)((KYBER_Q + 1) / 2), (ushort)((msg[i] >> j) & 1));
				}
			}
		}

		/*************************************************
		* Name:        poly_tomsg
		*
		* Description: Convert polynomial to 32-byte message
		*
		* Arguments:   - uint8_t *msg: pointer to output message
		*              - const poly *a: pointer to input polynomial
		**************************************************/
		private void poly_tomsg(byte[] msg, Poly a) {
			uint t;

			for (int i = 0; i < KYBER_N / 8; i++) {
				msg[i] = 0;
				for (int j = 0; j < 8; j++) {
					t = (uint)a.coeffs[(8 * i) + j];
					// t += ((int16_t)t >> 15) & KYBER_Q;
					// t  = (((t << 1) + KYBER_Q/2)/KYBER_Q) & 1;
					t <<= 1;
					t += 1665;
					t *= 80635;
					t >>= 28;
					t &= 1;
					msg[i] |= (byte)(t << j);
				}
			}
		}

		/*************************************************
		* Name:        poly_getnoise_eta1
		*
		* Description: Sample a polynomial deterministically from a seed and a nonce,
		*              with output polynomial close to centered binomial distribution
		*              with parameter KYBER_ETA1
		*
		* Arguments:   - poly *r: pointer to output polynomial
		*              - const uint8_t *seed: pointer to input seed
		*                                     (of length KYBER_SYMBYTES bytes)
		*              - uint8_t nonce: one-byte input nonce
		**************************************************/
		private void poly_getnoise_eta1(Poly r, Span<byte> seed, byte nonce) {
			byte[] buf;

			// FIXME - convert to span
			buf = kyber_shake256_prf(KYBER_ETA1 * KYBER_N / 4, seed, nonce); //prf(buf, buf.Length, seed, nonce);
			poly_cbd_eta1(r, buf);
		}

		/*************************************************
		* Name:        poly_getnoise_eta2
		*
		* Description: Sample a polynomial deterministically from a seed and a nonce,
		*              with output polynomial close to centered binomial distribution
		*              with parameter KYBER_ETA2
		*
		* Arguments:   - poly *r: pointer to output polynomial
		*              - const uint8_t *seed: pointer to input seed
		*                                     (of length KYBER_SYMBYTES bytes)
		*              - uint8_t nonce: one-byte input nonce
		**************************************************/
		private void poly_getnoise_eta2(Poly r, Span<byte> seed, byte nonce) {
			byte[] buf;

			buf = kyber_shake256_prf(KYBER_ETA2 * KYBER_N / 4, seed, nonce); //prf(buf, buf.Length, seed, nonce);
			poly_cbd_eta2(r, buf);
		}


		/*************************************************
		* Name:        poly_ntt
		*
		* Description: Computes negacyclic number-theoretic transform (NTT) of
		*              a polynomial in place;
		*              inputs assumed to be in normal order, output in bitreversed order
		*
		* Arguments:   - uint16_t *r: pointer to in/output polynomial
		**************************************************/
		private void poly_ntt(Poly r) {
			ntt(r.coeffs);
			poly_reduce(r);
		}

		/*************************************************
		* Name:        poly_invntt_tomont
		*
		* Description: Computes inverse of negacyclic number-theoretic transform (NTT)
		*              of a polynomial in place;
		*              inputs assumed to be in bitreversed order, output in normal order
		*
		* Arguments:   - uint16_t *a: pointer to in/output polynomial
		**************************************************/
		private void poly_invntt_tomont(Poly r) {
			invntt(r.coeffs);
		}

		/*************************************************
		* Name:        poly_basemul_montgomery
		*
		* Description: Multiplication of two polynomials in NTT domain
		*
		* Arguments:   - poly *r: pointer to output polynomial
		*              - const poly *a: pointer to first input polynomial
		*              - const poly *b: pointer to second input polynomial
		**************************************************/
		private void poly_basemul_montgomery(Poly r, Poly a, Poly b) {
			for (int i = 0; i < KYBER_N / 4; i++) {
				basemul(r.coeffs, 4 * i, a.coeffs, 4 * i, b.coeffs, 4 * i, zetas[64 + i]);
				basemul(r.coeffs, (4 * i) + 2, a.coeffs, (4 * i) + 2, b.coeffs, (4 * i) + 2, (short)-zetas[64 + i]);
			}
		}

		/*************************************************
		* Name:        poly_tomont
		*
		* Description: Inplace conversion of all coefficients of a polynomial
		*              from normal domain to Montgomery domain
		*
		* Arguments:   - poly *r: pointer to input/output polynomial
		**************************************************/
		private void poly_tomont(Poly r) {
			short f;

			f = (short)((1UL << 32) % (ulong)KYBER_Q);


			for (int i = 0; i < KYBER_N; i++) {
				r.coeffs[i] = montgomery_reduce(r.coeffs[i] * f);
			}
		}

		/*************************************************
		* Name:        poly_reduce
		*
		* Description: Applies Barrett reduction to all coefficients of a polynomial
		*              for details of the Barrett reduction see comments in reduce.c
		*
		* Arguments:   - poly *r: pointer to input/output polynomial
		**************************************************/
		private void poly_reduce(Poly r) {
			for (int i = 0; i < KYBER_N; i++) {
				r.coeffs[i] = barrett_reduce(r.coeffs[i]);
			}
		}

		/*************************************************
		* Name:        poly_add
		*
		* Description: Add two polynomials; no modular reduction is performed
		*
		* Arguments: - poly *r: pointer to output polynomial
		*            - const poly *a: pointer to first input polynomial
		*            - const poly *b: pointer to second input polynomial
		**************************************************/
		private void poly_add(Poly r, Poly a, Poly b) {
			for (int i = 0; i < KYBER_N; i++) {
				r.coeffs[i] = (short)(a.coeffs[i] + b.coeffs[i]);
			}
		}

		/*************************************************
		* Name:        poly_sub
		*
		* Description: Subtract two polynomials; no modular reduction is performed
		*
		* Arguments: - poly *r:       pointer to output polynomial
		*            - const poly *a: pointer to first input polynomial
		*            - const poly *b: pointer to second input polynomial
		**************************************************/
		private void poly_sub(Poly r, Poly a, Poly b) {
			for (int i = 0; i < KYBER_N; i++) {
				r.coeffs[i] = (short)(a.coeffs[i] - b.coeffs[i]);
			}
		}
	}
}