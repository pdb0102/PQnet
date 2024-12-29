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

using System.Diagnostics;

namespace PQnet {
	public abstract partial class MlKemBase {
		private class Polyvec {
			public Polyvec(int k, int n) {
				vec = new Poly[k];
				for (int i = 0; i < k; i++) {
					vec[i] = new Poly(n);
				}
			}
			public Poly[] vec;
		}
		/*************************************************
		* Name:        polyvec_compress
		*
		* Description: Compress and serialize vector of polynomials
		*
		* Arguments:   - uint8_t *r: pointer to output byte array
		*                            (needs space for KYBER_POLYVECCOMPRESSEDBYTES)
		*              - const polyvec *a: pointer to input vector of polynomials
		**************************************************/

		private void polyvec_compress(byte[] r, Polyvec a) {
			uint i, j, k;
			ulong d0;
			int r_offset;

			Debug.Assert(r.Length == KYBER_POLYVECCOMPRESSEDBYTES);

			r_offset = 0;

			if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352)) {
				ushort[] t;

				t = new ushort[8];

				for (i = 0; i < KYBER_K; i++) {
					for (j = 0; j < KYBER_N / 8; j++) {
						for (k = 0; k < 8; k++) {
							t[k] = (ushort)a.vec[i].coeffs[(8 * j) + k];
							t[k] += (ushort)(((short)t[k] >> 15) & KYBER_Q);
							/*      t[k]  = ((((uint32_t)t[k] << 11) + KYBER_Q/2)/KYBER_Q) & 0x7ff; */
							d0 = t[k];
							d0 <<= 11;
							d0 += 1664;
							d0 *= 645084;
							d0 >>= 31;
							t[k] = (ushort)(d0 & 0x7ff);

						}

						r[r_offset + 0] = (byte)(t[0] >> 0);
						r[r_offset + 1] = (byte)((t[0] >> 8) | (t[1] << 3));
						r[r_offset + 2] = (byte)((t[1] >> 5) | (t[2] << 6));
						r[r_offset + 3] = (byte)(t[2] >> 2);
						r[r_offset + 4] = (byte)((t[2] >> 10) | (t[3] << 1));
						r[r_offset + 5] = (byte)((t[3] >> 7) | (t[4] << 4));
						r[r_offset + 6] = (byte)((t[4] >> 4) | (t[5] << 7));
						r[r_offset + 7] = (byte)(t[5] >> 1);
						r[r_offset + 8] = (byte)((t[5] >> 9) | (t[6] << 2));
						r[r_offset + 9] = (byte)((t[6] >> 6) | (t[7] << 5));
						r[r_offset + 10] = (byte)(t[7] >> 3);
						r_offset += 11;
					}
				}
			} else if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320)) {
				ushort[] t;

				t = new ushort[4];

				for (i = 0; i < KYBER_K; i++) {
					for (j = 0; j < KYBER_N / 4; j++) {
						for (k = 0; k < 4; k++) {
							t[k] = (ushort)a.vec[i].coeffs[(4 * j) + k];
							t[k] += (ushort)(((short)t[k] >> 15) & KYBER_Q);
							/*      t[k]  = ((((uint32_t)t[k] << 10) + KYBER_Q/2)/ KYBER_Q) & 0x3ff; */
							d0 = t[k];
							d0 <<= 10;
							d0 += 1665;
							d0 *= 1290167;
							d0 >>= 32;
							t[k] = (ushort)(d0 & 0x3ff);
						}

						r[r_offset + 0] = (byte)(t[0] >> 0);
						r[r_offset + 1] = (byte)((t[0] >> 8) | (t[1] << 2));
						r[r_offset + 2] = (byte)((t[1] >> 6) | (t[2] << 4));
						r[r_offset + 3] = (byte)((t[2] >> 4) | (t[3] << 6));
						r[r_offset + 4] = (byte)(t[3] >> 2);
						r_offset += 5;
					}
				}
			} else {
				throw new Exception("KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}");
			}
		}

		/*************************************************
		* Name:        polyvec_decompress
		*
		* Description: De-serialize and decompress vector of polynomials;
		*              approximate inverse of polyvec_compress
		*
		* Arguments:   - polyvec *r:       pointer to output vector of polynomials
		*              - const uint8_t *a: pointer to input byte array
		*                                  (of length KYBER_POLYVECCOMPRESSEDBYTES)
		**************************************************/
		private void polyvec_decompress(Polyvec r, byte[] a) {
			uint i, j, k;
			int a_offset;

			Debug.Assert(a.Length == KYBER_POLYVECCOMPRESSEDBYTES);

			a_offset = 0;

			if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 352)) {
				ushort[] t;

				t = new ushort[8];

				for (i = 0; i < KYBER_K; i++) {
					for (j = 0; j < KYBER_N / 8; j++) {
						t[0] = (ushort)((a[a_offset + 0] >> 0) | (a[a_offset + 1] << 8));
						t[1] = (ushort)((a[a_offset + 1] >> 3) | (a[a_offset + 2] << 5));
						t[2] = (ushort)((a[a_offset + 2] >> 6) | (a[a_offset + 3] << 2) | (a[a_offset + 4] << 10));
						t[3] = (ushort)((a[a_offset + 4] >> 1) | (a[a_offset + 5] << 7));
						t[4] = (ushort)((a[a_offset + 5] >> 4) | (a[a_offset + 6] << 4));
						t[5] = (ushort)((a[a_offset + 6] >> 7) | (a[a_offset + 7] << 1) | (a[a_offset + 8] << 9));
						t[6] = (ushort)((a[a_offset + 8] >> 2) | (a[a_offset + 9] << 6));
						t[7] = (ushort)((a[a_offset + 9] >> 5) | (a[a_offset + 10] << 3));
						a_offset += 11;

						for (k = 0; k < 8; k++) {
							r.vec[i].coeffs[(8 * j) + k] = (short)((((uint)(t[k] & 0x7FF) * KYBER_Q) + 1024) >> 11);
						}
					}
				}
			} else if (KYBER_POLYVECCOMPRESSEDBYTES == (KYBER_K * 320)) {
				ushort[] t;

				t = new ushort[4];

				for (i = 0; i < KYBER_K; i++) {
					for (j = 0; j < KYBER_N / 4; j++) {
						t[0] = (ushort)((a[a_offset + 0] >> 0) | (a[a_offset + 1] << 8));
						t[1] = (ushort)((a[a_offset + 1] >> 2) | (a[a_offset + 2] << 6));
						t[2] = (ushort)((a[a_offset + 2] >> 4) | (a[a_offset + 3] << 4));
						t[3] = (ushort)((a[a_offset + 3] >> 6) | (a[a_offset + 4] << 2));
						a_offset += 5;

						for (k = 0; k < 4; k++) {
							r.vec[i].coeffs[(4 * j) + k] = (short)((((uint)(t[k] & 0x3FF) * KYBER_Q) + 512) >> 10);
						}
					}
				}
			} else {
				throw new Exception("KYBER_POLYVECCOMPRESSEDBYTES needs to be in {320*KYBER_K, 352*KYBER_K}");
			}
		}

		/*************************************************
		* Name:        polyvec_tobytes
		*
		* Description: Serialize vector of polynomials
		*
		* Arguments:   - uint8_t *r: pointer to output byte array
		*                            (needs space for KYBER_POLYVECBYTES)
		*              - const polyvec *a: pointer to input vector of polynomials
		**************************************************/
		private void polyvec_tobytes(byte[] r, Polyvec a) {
			int i;

			Debug.Assert(r.Length >= KYBER_POLYVECBYTES);

			for (i = 0; i < KYBER_K; i++) {
				poly_tobytes(r, i * KYBER_POLYBYTES, a.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyvec_frombytes
		*
		* Description: De-serialize vector of polynomials;
		*              inverse of polyvec_tobytes
		*
		* Arguments:   - uint8_t *r:       pointer to output byte array
		*              - const polyvec *a: pointer to input vector of polynomials
		*                                  (of length KYBER_POLYVECBYTES)
		**************************************************/
		private void polyvec_frombytes(Polyvec r, byte[] a) {
			int i;

			Debug.Assert(a.Length == KYBER_POLYVECBYTES);
			for (i = 0; i < KYBER_K; i++) {
				poly_frombytes(r.vec[i], a, i * KYBER_POLYBYTES);
			}
		}

		/*************************************************
		* Name:        polyvec_ntt
		*
		* Description: Apply forward NTT to all elements of a vector of polynomials
		*
		* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
		**************************************************/
		private void polyvec_ntt(Polyvec r) {
			int i;

			for (i = 0; i < KYBER_K; i++) {
				poly_ntt(r.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyvec_invntt_tomont
		*
		* Description: Apply inverse NTT to all elements of a vector of polynomials
		*              and multiply by Montgomery factor 2^16
		*
		* Arguments:   - polyvec *r: pointer to in/output vector of polynomials
		**************************************************/
		private void polyvec_invntt_tomont(Polyvec r) {
			int i;

			for (i = 0; i < KYBER_K; i++) {
				poly_invntt_tomont(r.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyvec_basemul_acc_montgomery
		*
		* Description: Multiply elements of a and b in NTT domain, accumulate into r,
		*              and multiply by 2^-16.
		*
		* Arguments: - poly *r: pointer to output polynomial
		*            - const polyvec *a: pointer to first input vector of polynomials
		*            - const polyvec *b: pointer to second input vector of polynomials
		**************************************************/
		private void polyvec_basemul_acc_montgomery(Poly r, Polyvec a, Polyvec b) {
			int i;
			Poly t;

			t = new Poly(KYBER_N);

			poly_basemul_montgomery(r, a.vec[0], b.vec[0]);
			for (i = 1; i < KYBER_K; i++) {
				poly_basemul_montgomery(t, a.vec[i], b.vec[i]);
				poly_add(r, r, t);
			}

			poly_reduce(r);
		}

		/*************************************************
		* Name:        polyvec_reduce
		*
		* Description: Applies Barrett reduction to each coefficient
		*              of each element of a vector of polynomials;
		*              for details of the Barrett reduction see comments in reduce.c
		*
		* Arguments:   - polyvec *r: pointer to input/output polynomial
		**************************************************/
		private void polyvec_reduce(Polyvec r) {
			int i;

			for (i = 0; i < KYBER_K; i++) {
				poly_reduce(r.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyvec_add
		*
		* Description: Add vectors of polynomials
		*
		* Arguments: - polyvec *r: pointer to output vector of polynomials
		*            - const polyvec *a: pointer to first input vector of polynomials
		*            - const polyvec *b: pointer to second input vector of polynomials
		**************************************************/
		private void polyvec_add(Polyvec r, Polyvec a, Polyvec b) {
			int i;
			for (i = 0; i < KYBER_K; i++)
				poly_add(r.vec[i], a.vec[i], b.vec[i]);
		}
	}
}