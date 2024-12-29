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
		/*************************************************
		* Name:        load32_littleendian
		*
		* Description: load 4 bytes into a 32-bit integer
		*              in little-endian order
		*
		* Arguments:   - const byte *x: pointer to input byte array
		*
		* Returns 32-bit unsigned integer loaded from x
		**************************************************/

		private static uint load32_littleendian(byte[] x, int offset) {
			Debug.Assert(x.Length >= 4);

			return x[offset + 0] | ((uint)x[offset + 1] << 8) | ((uint)x[offset + 2] << 16) | ((uint)x[offset + 3] << 24);
		}

		/*************************************************
		* Name:        load24_littleendian
		*
		* Description: load 3 bytes into a 32-bit integer
		*              in little-endian order.
		*              This function is only needed for Kyber-512
		*
		* Arguments:   - const byte *x: pointer to input byte array
		*
		* Returns 32-bit unsigned integer loaded from x (most significant byte is zero)
		**************************************************/
		private static uint load24_littleendian(byte[] x, int offset) {
			Debug.Assert(x.Length >= 3);

			return x[offset + 0] | ((uint)x[offset + 1] << 8) | ((uint)x[offset + 2] << 16);
		}


		/*************************************************
		* Name:        cbd2
		*
		* Description: Given an array of uniformly random bytes, compute
		*              polynomial with coefficients distributed according to
		*              a centered binomial distribution with parameter eta=2
		*
		* Arguments:   - poly *r: pointer to output polynomial
		*              - const byte *buf: pointer to input byte array
		**************************************************/
		private void cbd2(Poly r, byte[] buf) {
			uint t;
			uint d;
			short a;
			short b;

			Debug.Assert(buf.Length == 2 * KYBER_N / 4);

			for (int i = 0; i < KYBER_N / 8; i++) {
				t = load32_littleendian(buf, 4 * i);
				d = t & 0x55555555;
				d += (t >> 1) & 0x55555555;

				for (int j = 0; j < 8; j++) {
					a = (short)((d >> ((4 * j) + 0)) & 0x3);
					b = (short)((d >> ((4 * j) + 2)) & 0x3);
					r.coeffs[(8 * i) + j] = (short)(a - b);
				}
			}
		}

		/*************************************************
		* Name:        cbd3
		*
		* Description: Given an array of uniformly random bytes, compute
		*              polynomial with coefficients distributed according to
		*              a centered binomial distribution with parameter eta=3.
		*              This function is only needed for Kyber-512
		*
		* Arguments:   - poly *r: pointer to output polynomial
		*              - const byte *buf: pointer to input byte array
		**************************************************/
		private void cbd3(Poly r, byte[] buf) {
			uint t;
			uint d;
			short a;
			short b;

			Debug.Assert(buf.Length == 3 * KYBER_N / 4);

			for (int i = 0; i < KYBER_N / 4; i++) {
				t = load24_littleendian(buf, 3 * i);
				d = t & 0x00249249;
				d += (t >> 1) & 0x00249249;
				d += (t >> 2) & 0x00249249;

				for (int j = 0; j < 4; j++) {
					a = (short)((d >> ((6 * j) + 0)) & 0x7);
					b = (short)((d >> ((6 * j) + 3)) & 0x7);
					r.coeffs[(4 * i) + j] = (short)(a - b);
				}
			}
		}

		private void poly_cbd_eta1(Poly r, byte[] buf) {
			Debug.Assert(buf.Length == KYBER_ETA1 * KYBER_N / 4);

			if (KYBER_ETA1 == 2) {
				cbd2(r, buf);
			} else if (KYBER_ETA1 == 3) {
				cbd3(r, buf);
			} else {
				throw new System.NotSupportedException("This implementation requires eta1 in {2,3}");
			}
		}

		private void poly_cbd_eta2(Poly r, byte[] buf) {
			Debug.Assert(buf.Length == KYBER_ETA2 * KYBER_N / 4);
			if (KYBER_ETA2 == 2) {
				cbd2(r, buf);
			} else {
				throw new System.NotSupportedException("This implementation requires eta2 = 2");
			}
		}
	}
}
