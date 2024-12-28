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

namespace PQnet.ML_DSA {

	public abstract partial class MlDsaBase {
		private const int QINV = 58728449; // q^(-1) mod 2^32


		/// <summary>
		/// Montgomery reduction; given a 64-bit integer a, computes 32-bit integer congruent to a * R^-1 mod Q,
		/// </summary>
		/// <param name="a">finite field element a</param>
		/// <returns>r</returns>
		/// <remarks>
		/// For finite field element a with -2^{31}Q <= a <= Q*2^31, compute r \equiv a*2^{-32} (mod Q) such that -Q < r < Q.
		/// </remarks>
		private int montgomery_reduce(long a) {
			int t;

			t = (int)a * QINV;
			t = (int)((a - ((long)t * Q)) >> 32);
			return t;
		}

		/// <summary>
		/// Reduce a coefficient a mod Q.
		/// </summary>
		/// <param name="a">finite field element a</param>
		/// <returns>r</returns>
		/// <remarks>
		/// For finite field element a with a <= 2^{31} - 2^{22} - 1, compute r \equiv a (mod Q) such that -6283008 <= r <= 6283008.
		/// </remarks>
		private int reduce32(int a) {
			int t;

			t = (a + (1 << 22)) >> 23;
			t = a - (t * Q);
			return t;
		}

		/// <summary>
		/// Add Q if input coefficient is negative.
		/// </summary>
		/// <param name="a">finite field element a</param>
		/// <returns>r</returns>
		private int caddq(int a) {
			a += (a >> 31) & Q;
			return a;
		}

		/// <summary>
		/// 
		/// </summary>
		/// <param name="a">finite field element a</param>
		/// <returns>r</returns>
		/// <remarks>
		/// For finite field element a, compute standard representative r = a mod^+ Q.
		/// </remarks>
		private int freeze(int a) {
			a = reduce32(a);
			a = caddq(a);
			return a;
		}

	}
}