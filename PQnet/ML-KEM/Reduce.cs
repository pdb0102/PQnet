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

namespace PQnet {
	public abstract partial class MlKemBase {
		private const int QINV = -3327; // -q^(-1) mod 2^16

		/*************************************************
		* Name:        montgomery_reduce
		*
		* Description: Montgomery reduction; given a 32-bit integer a, computes
		*              16-bit integer congruent to a * R^-1 mod q, where R=2^16
		*
		* Arguments:   - int32_t a: input integer to be reduced;
		*                           has to be in {-q2^15,...,q2^15-1}
		*
		* Returns:     integer in {-q+1,...,q-1} congruent to a * R^-1 modulo q.
		**************************************************/
		private short montgomery_reduce(int a) {
			short t;

			t = (short)(a * QINV);
			t = (short)((a - (t * KYBER_Q)) >> 16);
			return t;
		}

		/*************************************************
		* Name:        barrett_reduce
		*
		* Description: Barrett reduction; given a 16-bit integer a, computes
		*              centered representative congruent to a mod q in {-(q-1)/2,...,(q-1)/2}
		*
		* Arguments:   - int16_t a: input integer to be reduced
		*
		* Returns:     integer in {-(q-1)/2,...,(q-1)/2} congruent to a modulo q.
		**************************************************/
		private short barrett_reduce(short a) {
			short t;
			short v = (short)(((1 << 26) + (KYBER_Q / 2)) / KYBER_Q);

			t = (short)(((v * a) + (1 << 25)) >> 26);
			t *= (short)KYBER_Q;
			return (short)(a - t);
		}
	}
}