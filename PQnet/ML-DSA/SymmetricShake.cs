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

using PQnet.Digest;

namespace PQnet {
	public abstract partial class MlDsaBase {
		private const int STREAM128_BLOCKBYTES = Shake.SHAKE128_RATE;
		private const int STREAM256_BLOCKBYTES = Shake.SHAKE256_RATE;

		private void dilithium_shake128_stream_init(Shake.keccak_state state, byte[] seed, ushort nonce) {
			byte[] t;

			t = new byte[2];
			t[0] = (byte)(nonce & 0xff);
			t[1] = (byte)(nonce >> 8);

			Debug.Assert(seed.Length >= SeedBytes);

			Shake.shake128_init(state);
			Shake.shake128_absorb(state, seed, SeedBytes);
			Shake.shake128_absorb(state, t, 2);
			Shake.shake128_finalize(state);
		}


		void dilithium_shake256_stream_init(Shake.keccak_state state, byte[] seed, ushort nonce) {
			byte[] t;

			t = new byte[2];
			t[0] = (byte)(nonce & 0xff);
			t[1] = (byte)(nonce >> 8);

			Shake.shake256_init(state);
			Shake.shake256_absorb(state, seed, CrhBytes);
			Shake.shake256_absorb(state, t, 2);
			Shake.shake256_finalize(state);
		}
	}
}