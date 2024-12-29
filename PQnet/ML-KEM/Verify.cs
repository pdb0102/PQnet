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
		* Name:        verify
		*
		* Description: Compare two arrays for equality in constant time.
		*
		* Arguments:   const byte *a: pointer to first byte array
		*              const byte *b: pointer to second byte array
		*              int len:       length of the byte arrays
		*
		* Returns 0 if the byte arrays are equal, 1 otherwise
		**************************************************/
		int verify(byte[] a, byte[] b, int len) {
			int i;
			byte r = 0;

			for (i = 0; i < len; i++) {
				r |= (byte)(a[i] ^ b[i]);
			}

			return (int)(((~(ulong)r + 1) >> 63) & 1);
		}

		/*************************************************
		* Name:        cmov
		*
		* Description: Copy len bytes from x to r if b is 1;
		*              don't modify x if b is 0. Requires b to be in {0,1};
		*              assumes two's complement representation of negative integers.
		*              Runs in constant time.
		*
		* Arguments:   byte *r:       pointer to output byte array
		*              const byte *x: pointer to input byte array
		*              int len:       Amount of bytes to be copied
		*              byte b:        Condition bit; has to be in {0,1}
		**************************************************/
		void cmov(byte[] r, byte[] x, int len, byte b) {
			int i;

			b = (byte)-b;
			for (i = 0; i < len; i++) {
				r[i] ^= (byte)(b & (r[i] ^ x[i]));
			}
		}


		/*************************************************
		* Name:        cmov_int16
		*
		* Description: Copy input v to *r if b is 1, don't modify *r if b is 0. 
		*              Requires b to be in {0,1};
		*              Runs in constant time.
		*
		* Arguments:   short *r:       pointer to output short
		*              short v:        input short 
		*              byte b:        Condition bit; has to be in {0,1}
		**************************************************/
		void cmov_int16(ref short r, short v, ushort b) {
			b = (ushort)-b;
			r ^= (short)(b & ((r) ^ v));
		}
	}
}