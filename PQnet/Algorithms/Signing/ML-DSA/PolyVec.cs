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

// Ported from the reference implementation found at https://www.pq-crystals.org/dilithium/

using System.Diagnostics;

namespace PQnet {
	public abstract partial class MlDsaBase {
		private class PolyVecK {
			private int k;
			private int n;

			private PolyVecK(int K) {
				k = K;
				vec = new Poly[k];
			}

			public PolyVecK(int K, int N) {
				k = K;
				n = N;

				vec = new Poly[K];
				for (int i = 0; i < K; i++) {
					vec[i] = new Poly(N);
				}
			}

			public PolyVecK Clone() {
				PolyVecK clone;

				clone = new PolyVecK(k);
				clone.k = k;
				clone.n = n;
				for (int i = 0; i < k; i++) {
					clone.vec[i] = vec[i].Clone();
				}
				return clone;

			}

			public Poly[] vec;
		}

		private class PolyVecL {
			private int l;
			private int n;

			private PolyVecL(int L) {
				l = L;
				vec = new Poly[L];
			}

			public PolyVecL(int L, int N) {
				l = L;
				n = N;

				vec = new Poly[L];
				for (int i = 0; i < L; i++) {
					vec[i] = new Poly(N);
				}
			}

			public PolyVecL Clone() {
				PolyVecL clone;

				clone = new PolyVecL(l);
				clone.l = l;
				clone.n = n;
				for (int i = 0; i < l; i++) {
					clone.vec[i] = vec[i].Clone();
				}
				return clone;

			}

			public Poly[] vec;
		}


		/*************************************************
		* Name:        expand_mat
		*
		* Description: Implementation of ExpandA. Generates matrix A with uniformly
		*              random coefficients a_{i,j} by performing rejection
		*              sampling on the output stream of SHAKE128(rho|j|i)
		*
		* Arguments:   - polyvecl mat[K]: output matrix
		*              - const uint8_t rho[]: byte array containing seed rho
		**************************************************/
		private void polyvec_matrix_expand(PolyVecL[] mat, byte[] rho) {
			Debug.Assert(mat.Length == K);

			for (int i = 0; i < K; i++) {
				for (int j = 0; j < L; j++) {
					poly_uniform(mat[i].vec[j], rho, (ushort)((i << 8) + j));
				}
			}
		}

		private void polyvec_matrix_pointwise_montgomery(PolyVecK t, PolyVecL[] mat, PolyVecL v) {
			for (int i = 0; i < K; i++) {
				polyvecl_pointwise_acc_montgomery(t.vec[i], mat[i], v);
			}
		}

		/**************************************************************/
		/************ Vectors of polynomials of length L **************/
		/**************************************************************/

		private void polyvecl_uniform_eta(PolyVecL v, byte[] seed, ushort nonce) {
			for (int i = 0; i < L; i++) {
				poly_uniform_eta(v.vec[i], seed, nonce++);
			}
		}

		private void polyvecl_uniform_gamma1(PolyVecL v, byte[] seed, ushort nonce) {
			for (int i = 0; i < L; i++) {
				poly_uniform_gamma1(v.vec[i], seed, (ushort)((L * nonce) + i));
			}
		}

		private void polyvecl_reduce(PolyVecL v) {
			for (int i = 0; i < L; i++) {
				poly_reduce(v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyvecl_add
		*
		* Description: Add vectors of polynomials of length L.
		*              No modular reduction is performed.
		*
		* Arguments:   - polyvecl *w: pointer to output vector
		*              - const polyvecl *u: pointer to first summand
		*              - const polyvecl *v: pointer to second summand
		**************************************************/
		private void polyvecl_add(PolyVecL w, PolyVecL u, PolyVecL v) {
			for (int i = 0; i < L; i++) {
				poly_add(w.vec[i], u.vec[i], v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyvecl_ntt
		*
		* Description: Forward NTT of all polynomials in vector of length L. Output
		*              coefficients can be up to 16*Q larger than input coefficients.
		*
		* Arguments:   - polyvecl *v: pointer to input/output vector
		**************************************************/
		private void polyvecl_ntt(PolyVecL v) {
			for (int i = 0; i < L; i++) {
				poly_ntt(v.vec[i]);
			}
		}

		private void polyvecl_invntt_tomont(PolyVecL v) {
			for (int i = 0; i < L; i++) {
				poly_invntt_tomont(v.vec[i]);
			}
		}

		private void polyvecl_pointwise_poly_montgomery(PolyVecL r, Poly a, PolyVecL v) {
			for (int i = 0; i < L; i++) {
				poly_pointwise_montgomery(r.vec[i], a, v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyvecl_pointwise_acc_montgomery
		*
		* Description: Pointwise multiply vectors of polynomials of length L, multiply
		*              resulting vector by 2^{-32} and add (accumulate) polynomials
		*              in it. Input/output vectors are in NTT domain representation.
		*
		* Arguments:   - poly *w: output polynomial
		*              - const polyvecl *u: pointer to first input vector
		*              - const polyvecl *v: pointer to second input vector
		**************************************************/
		private void polyvecl_pointwise_acc_montgomery(Poly w, PolyVecL u, PolyVecL v) {
			Poly t;

			t = new Poly(N);

			poly_pointwise_montgomery(w, u.vec[0], v.vec[0]);
			for (int i = 1; i < L; i++) {
				poly_pointwise_montgomery(t, u.vec[i], v.vec[i]);
				poly_add(w, w, t);
			}
		}

		/*************************************************
		* Name:        polyvecl_chknorm
		*
		* Description: Check infinity norm of polynomials in vector of length L.
		*              Assumes input polyvecl to be reduced by polyvecl_reduce().
		*
		* Arguments:   - const polyvecl *v: pointer to vector
		*              - int B: norm bound
		*
		* Returns 0 if norm of all polynomials is strictly smaller than B <= (Q-1)/8
		* and 1 otherwise.
		**************************************************/
		private int polyvecl_chknorm(PolyVecL v, int bound) {
			for (int i = 0; i < L; i++) {
				if (poly_chknorm(v.vec[i], bound) == 1) {
					return 1;
				}
			}

			return 0;
		}

		/**************************************************************/
		/************ Vectors of polynomials of length K **************/
		/**************************************************************/

		private void polyveck_uniform_eta(PolyVecK v, byte[] seed, ushort nonce) {
			for (int i = 0; i < K; i++) {
				poly_uniform_eta(v.vec[i], seed, nonce++);
			}
		}

		/*************************************************
		* Name:        polyveck_reduce
		*
		* Description: Reduce coefficients of polynomials in vector of length K
		*              to representatives in [-6283008,6283008].
		*
		* Arguments:   - polyveck *v: pointer to input/output vector
		**************************************************/
		private void polyveck_reduce(PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_reduce(v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyveck_caddq
		*
		* Description: For all coefficients of polynomials in vector of length K
		*              add Q if coefficient is negative.
		*
		* Arguments:   - polyveck *v: pointer to input/output vector
		**************************************************/
		private void polyveck_caddq(PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_caddq(v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyveck_add
		*
		* Description: Add vectors of polynomials of length K.
		*              No modular reduction is performed.
		*
		* Arguments:   - polyveck *w: pointer to output vector
		*              - const polyveck *u: pointer to first summand
		*              - const polyveck *v: pointer to second summand
		**************************************************/
		private void polyveck_add(PolyVecK w, PolyVecK u, PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_add(w.vec[i], u.vec[i], v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyveck_sub
		*
		* Description: Subtract vectors of polynomials of length K.
		*              No modular reduction is performed.
		*
		* Arguments:   - polyveck *w: pointer to output vector
		*              - const polyveck *u: pointer to first input vector
		*              - const polyveck *v: pointer to second input vector to be
		*                                   subtracted from first input vector
		**************************************************/
		private void polyveck_sub(PolyVecK w, PolyVecK u, PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_sub(w.vec[i], u.vec[i], v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyveck_shiftl
		*
		* Description: Multiply vector of polynomials of Length K by 2^D without modular
		*              reduction. Assumes input coefficients to be less than 2^{31-D}.
		*
		* Arguments:   - polyveck *v: pointer to input/output vector
		**************************************************/
		private void polyveck_shiftl(PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_shiftl(v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyveck_ntt
		*
		* Description: Forward NTT of all polynomials in vector of length K. Output
		*              coefficients can be up to 16*Q larger than input coefficients.
		*
		* Arguments:   - polyveck *v: pointer to input/output vector
		**************************************************/
		private void polyveck_ntt(PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_ntt(v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyveck_invntt_tomont
		*
		* Description: Inverse NTT and multiplication by 2^{32} of polynomials
		*              in vector of length K. Input coefficients need to be less
		*              than 2*Q.
		*
		* Arguments:   - polyveck *v: pointer to input/output vector
		**************************************************/
		private void polyveck_invntt_tomont(PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_invntt_tomont(v.vec[i]);
			}
		}

		private void polyveck_pointwise_poly_montgomery(PolyVecK r, Poly a, PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_pointwise_montgomery(r.vec[i], a, v.vec[i]);
			}
		}


		/*************************************************
		* Name:        polyveck_chknorm
		*
		* Description: Check infinity norm of polynomials in vector of length K.
		*              Assumes input polyveck to be reduced by polyveck_reduce().
		*
		* Arguments:   - const polyveck *v: pointer to vector
		*              - int B: norm bound
		*
		* Returns 0 if norm of all polynomials are strictly smaller than B <= (Q-1)/8
		* and 1 otherwise.
		**************************************************/
		int polyveck_chknorm(PolyVecK v, int bound) {
			for (int i = 0; i < K; i++) {
				if (poly_chknorm(v.vec[i], bound) == 1) {
					return 1;
				}
			}

			return 0;
		}

		/*************************************************
		* Name:        polyveck_power2round
		*
		* Description: For all coefficients a of polynomials in vector of length K,
		*              compute a0, a1 such that a mod^+ Q = a1*2^D + a0
		*              with -2^{D-1} < a0 <= 2^{D-1}. Assumes coefficients to be
		*              standard representatives.
		*
		* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
		*                              coefficients a1
		*              - polyveck *v0: pointer to output vector of polynomials with
		*                              coefficients a0
		*              - const polyveck *v: pointer to input vector
		**************************************************/
		private void polyveck_power2round(PolyVecK v1, PolyVecK v0, PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_power2round(v1.vec[i], v0.vec[i], v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyveck_decompose
		*
		* Description: For all coefficients a of polynomials in vector of length K,
		*              compute high and low bits a0, a1 such a mod^+ Q = a1*ALPHA + a0
		*              with -ALPHA/2 < a0 <= ALPHA/2 except a1 = (Q-1)/ALPHA where we
		*              set a1 = 0 and -ALPHA/2 <= a0 = a mod Q - Q < 0.
		*              Assumes coefficients to be standard representatives.
		*
		* Arguments:   - polyveck *v1: pointer to output vector of polynomials with
		*                              coefficients a1
		*              - polyveck *v0: pointer to output vector of polynomials with
		*                              coefficients a0
		*              - const polyveck *v: pointer to input vector
		**************************************************/
		private void polyveck_decompose(PolyVecK v1, PolyVecK v0, PolyVecK v) {
			for (int i = 0; i < K; i++) {
				poly_decompose(v1.vec[i], v0.vec[i], v.vec[i]);
			}
		}

		/*************************************************
		* Name:        polyveck_make_hint
		*
		* Description: Compute hint vector.
		*
		* Arguments:   - polyveck *h: pointer to output vector
		*              - const polyveck *v0: pointer to low part of input vector
		*              - const polyveck *v1: pointer to high part of input vector
		*
		* Returns number of 1 bits.
		**************************************************/
		private uint polyveck_make_hint(PolyVecK h, PolyVecK v0, PolyVecK v1) {
			uint s;

			s = 0;

			for (int i = 0; i < K; i++) {
				s += poly_make_hint(h.vec[i], v0.vec[i], v1.vec[i]);
			}

			return s;
		}

		/*************************************************
		* Name:        polyveck_use_hint
		*
		* Description: Use hint vector to correct the high bits of input vector.
		*
		* Arguments:   - polyveck *w: pointer to output vector of polynomials with
		*                             corrected high bits
		*              - const polyveck *u: pointer to input vector
		*              - const polyveck *h: pointer to input hint vector
		**************************************************/
		private void polyveck_use_hint(PolyVecK w, PolyVecK u, PolyVecK h) {
			for (int i = 0; i < K; i++) {
				poly_use_hint(w.vec[i], u.vec[i], h.vec[i]);
			}
		}

		private void polyveck_pack_w1(byte[] r, PolyVecK w1) {
			for (int i = 0; i < K; i++) {
				polyw1_pack(r, i * PolyW1PackedBytes, w1.vec[i]);
			}
		}
	}
}