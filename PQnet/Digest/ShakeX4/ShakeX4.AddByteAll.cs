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

using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PQnet.Digest {
	public partial class ShakeX4 {
		/// <summary>
		/// Add (in GC(2), using bitwise exclusive OR) the byte <paramref name="data"/> to the state at <paramref name="state_offset"/>.
		/// </summary>
		/// <param name="data">The byte to consume</param>
		/// <param name="state_offset">Offset, in bytes, within the state</param>
		public void AddByteAll(int state_offset, byte data) {
			int lane_position;
			ulong consume;

			lane_position = state_offset / 8;

			consume = (ulong)data << ((state_offset & 7) << 3); // data << ((state_offset % 8) * 8)

			state[lane_position] = Avx2.Xor(state[lane_position], Vector256.Create(consume, consume, consume, consume));
		}
	}
}
