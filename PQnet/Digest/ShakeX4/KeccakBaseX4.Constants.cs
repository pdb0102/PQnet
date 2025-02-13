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

using System.Runtime.Intrinsics;

namespace PQnet.Digest {
	public partial class KeccakBaseX4 {
		private static Vector256<byte> rho8 = Vector256.Create(0x0605040302010007u, 0x0E0D0C0B0A09080F, 0x1615141312111017, 0x1E1D1C1B1A19181F).AsByte();
		private static Vector256<byte> rho56 = Vector256.Create(0x0007060504030201u, 0x080F0E0D0C0B0A09, 0x1017161514131211, 0x181F1E1D1C1B1A19).AsByte();

		private static Vector256<ulong>[] KeccakF1600RoundConstants = {
			Vector256.Create(0x0000000000000001UL, 0x0000000000000001UL, 0x0000000000000001UL, 0x0000000000000001UL),
			Vector256.Create(0x0000000000008082UL, 0x0000000000008082UL, 0x0000000000008082UL, 0x0000000000008082UL),
			Vector256.Create(0x800000000000808aUL, 0x800000000000808aUL, 0x800000000000808aUL, 0x800000000000808aUL),
			Vector256.Create(0x8000000080008000UL, 0x8000000080008000UL, 0x8000000080008000UL, 0x8000000080008000UL),
			Vector256.Create(0x000000000000808bUL, 0x000000000000808bUL, 0x000000000000808bUL, 0x000000000000808bUL),
			Vector256.Create(0x0000000080000001UL, 0x0000000080000001UL, 0x0000000080000001UL, 0x0000000080000001UL),
			Vector256.Create(0x8000000080008081UL, 0x8000000080008081UL, 0x8000000080008081UL, 0x8000000080008081UL),
			Vector256.Create(0x8000000000008009UL, 0x8000000000008009UL, 0x8000000000008009UL, 0x8000000000008009UL),
			Vector256.Create(0x000000000000008aUL, 0x000000000000008aUL, 0x000000000000008aUL, 0x000000000000008aUL),
			Vector256.Create(0x0000000000000088UL, 0x0000000000000088UL, 0x0000000000000088UL, 0x0000000000000088UL),
			Vector256.Create(0x0000000080008009UL, 0x0000000080008009UL, 0x0000000080008009UL, 0x0000000080008009UL),
			Vector256.Create(0x000000008000000aUL, 0x000000008000000aUL, 0x000000008000000aUL, 0x000000008000000aUL),
			Vector256.Create(0x000000008000808bUL, 0x000000008000808bUL, 0x000000008000808bUL, 0x000000008000808bUL),
			Vector256.Create(0x800000000000008bUL, 0x800000000000008bUL, 0x800000000000008bUL, 0x800000000000008bUL),
			Vector256.Create(0x8000000000008089UL, 0x8000000000008089UL, 0x8000000000008089UL, 0x8000000000008089UL),
			Vector256.Create(0x8000000000008003UL, 0x8000000000008003UL, 0x8000000000008003UL, 0x8000000000008003UL),
			Vector256.Create(0x8000000000008002UL, 0x8000000000008002UL, 0x8000000000008002UL, 0x8000000000008002UL),
			Vector256.Create(0x8000000000000080UL, 0x8000000000000080UL, 0x8000000000000080UL, 0x8000000000000080UL),
			Vector256.Create(0x000000000000800aUL, 0x000000000000800aUL, 0x000000000000800aUL, 0x000000000000800aUL),
			Vector256.Create(0x800000008000000aUL, 0x800000008000000aUL, 0x800000008000000aUL, 0x800000008000000aUL),
			Vector256.Create(0x8000000080008081UL, 0x8000000080008081UL, 0x8000000080008081UL, 0x8000000080008081UL),
			Vector256.Create(0x8000000000008080UL, 0x8000000000008080UL, 0x8000000000008080UL, 0x8000000000008080UL),
			Vector256.Create(0x0000000080000001UL, 0x0000000080000001UL, 0x0000000080000001UL, 0x0000000080000001UL),
			Vector256.Create(0x8000000080008008UL, 0x8000000080008008UL, 0x8000000080008008UL, 0x8000000080008008UL),
		};
	}
}