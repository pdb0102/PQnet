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

namespace PQnet {
	public abstract partial class MlKemBase {
		private static short[] zetas = {
			-1044,  -758,  -359, -1517,  1493,  1422,   287,   202,
			 -171,   622,  1577,   182,   962, -1202, -1474,  1468,
			  573, -1325,   264,   383,  -829,  1458, -1602,  -130,
			 -681,  1017,   732,   608, -1542,   411,  -205, -1571,
			 1223,   652,  -552,  1015, -1293,  1491,  -282, -1544,
			  516,    -8,  -320,  -666, -1618, -1162,   126,  1469,
			 -853,   -90,  -271,   830,   107, -1421,  -247,  -951,
			 -398,   961, -1508,  -725,   448, -1065,   677, -1275,
			-1103,   430,   555,   843, -1251,   871,  1550,   105,
			  422,   587,   177,  -235,  -291,  -460,  1574,  1653,
			 -246,   778,  1159,  -147,  -777,  1483,  -602,  1119,
			-1590,   644,  -872,   349,   418,   329,  -156,   -75,
			  817,  1097,   603,   610,  1322, -1285, -1465,   384,
			-1215,  -136,  1218, -1335,  -874,   220, -1187, -1659,
			-1185, -1530, -1278,   794, -1510,  -854,  -870,   478,
			 -108,  -308,   996,   991,   958, -1460,  1522,  1628
		};

		/*************************************************
		* Name:        fqmul
		*
		* Description: Multiplication followed by Montgomery reduction
		*
		* Arguments:   - int16_t a: first factor
		*              - int16_t b: second factor
		*
		* Returns 16-bit integer congruent to a*b*R^{-1} mod q
		**************************************************/
		private short fqmul(short a, short b) {
			return montgomery_reduce(a * b);
		}

		/*************************************************
		* Name:        ntt
		*
		* Description: Inplace number-theoretic transform (NTT) in Rq.
		*              input is in standard order, output is in bitreversed order
		*
		* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
		**************************************************/
		private void ntt(short[] r) {
			uint len, start, j, k;
			short t, zeta;

			Debug.Assert(r.Length == 256);

			k = 1;
			for (len = 128; len >= 2; len >>= 1) {
				for (start = 0; start < 256; start = j + len) {
					zeta = zetas[k++];
					for (j = start; j < start + len; j++) {
						t = fqmul(zeta, r[j + len]);
						r[j + len] = (short)(r[j] - t);
						r[j] = (short)(r[j] + t);
					}
				}
			}
		}

		/*************************************************
		* Name:        invntt_tomont
		*
		* Description: Inplace inverse number-theoretic transform in Rq and
		*              multiplication by Montgomery factor 2^16.
		*              Input is in bitreversed order, output is in standard order
		*
		* Arguments:   - int16_t r[256]: pointer to input/output vector of elements of Zq
		**************************************************/
		private void invntt(short[] r) {
			uint start, len, j, k;
			short t, zeta;
			short f = 1441; // mont^2/128

			Debug.Assert(r.Length == 256);

			k = 127;
			for (len = 2; len <= 128; len <<= 1) {
				for (start = 0; start < 256; start = j + len) {
					zeta = zetas[k--];
					for (j = start; j < start + len; j++) {
						t = r[j];
						r[j] = barrett_reduce((short)(t + r[j + len]));
						r[j + len] = (short)(r[j + len] - t);
						r[j + len] = fqmul(zeta, r[j + len]);
					}
				}
			}

			for (j = 0; j < 256; j++) {
				r[j] = fqmul(r[j], f);
			}
		}

		/*************************************************
		* Name:        basemul
		*
		* Description: Multiplication of polynomials in Zq[X]/(X^2-zeta)
		*              used for multiplication of elements in Rq in NTT domain
		*
		* Arguments:   - int16_t r[2]: pointer to the output polynomial
		*              - const int16_t a[2]: pointer to the first factor
		*              - const int16_t b[2]: pointer to the second factor
		*              - int16_t zeta: integer defining the reduction polynomial
		**************************************************/
		private void basemul(short[] r, int r_index, short[] a, int a_index, short[] b, int b_index, short zeta) {
			r[r_index + 0] = fqmul(a[a_index + 1], b[b_index + 1]);
			r[r_index + 0] = fqmul(r[r_index + 0], zeta);
			r[r_index + 0] += fqmul(a[a_index + 0], b[b_index + 0]);
			r[r_index + 1] = fqmul(a[a_index + 0], b[b_index + 1]);
			r[r_index + 1] += fqmul(a[a_index + 1], b[b_index + 0]);
		}
	}
}