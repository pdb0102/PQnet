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
		/// Add (in GC(2), using bitwise exclusive OR) the bytes of <paramref name="data"/> to the state at <paramref name="state_offset"/> for <paramref name="length"/> bytes.
		/// </summary>
		/// <param name="instance">The instance to which to add the bytes (0-3)</param>
		/// <param name="state_offset">Offset, in bytes, within the state</param>
		/// <param name="data">The data to consume</param>
		/// <param name="length">The number of bytes of <paramref name="data"/> to consume</param>
		public void AddBytes(int instance, int state_offset, byte[] data, int length) {
			Vector256<ulong> v;
			int bytes_left;
			int instance_position;
			int offset;

			offset = 0;
			bytes_left = length;

			while (state_offset % 8 != 0) {
				// Consume enough bytes to be aligned on an 8-byte boundary so we can do whole chunks below
				AddByte(instance, state_offset++, data[offset++]);
				bytes_left--;
			}

			instance_position = state_offset / 8;
			while (bytes_left > 0) {
				v = state[instance_position];
				ulong consume;

				// Fixme - switch to Vector256.LoadUnsafe for consume and skip the create in the switch

				if (bytes_left >= 8) {
					// BitConverter.ToUInt64 is faster than accessing each byte and shifting
					consume = BitConverter.ToUInt64(data, offset);

					// We consumed 8 bytes
					offset += 8;
					bytes_left -= 8;
				} else {
					consume = 0;
					for (int i = 0; i < bytes_left; i++) {
						consume |= (ulong)data[offset++] << (i * 8);
					}
					bytes_left = 0;
				}
#if true
				switch (instance) {
					case 0:
						state[instance_position] = Avx2.Xor(v, Vector256.Create(consume, 0, 0, 0));
						break;

					case 1:
						state[instance_position] = Avx2.Xor(v, Vector256.Create(0, consume, 0, 0));
						break;

					case 2:
						state[instance_position] = Avx2.Xor(v, Vector256.Create(0, 0, consume, 0));
						break;

					case 3:
						state[instance_position] = Avx2.Xor(v, Vector256.Create(0, 0, 0, consume));
						break;
				}
#else
				// This is slower than the Avx2.Xor version
				switch (lane) {
					case 0:
						state[lane_position] = Vector256.Create(v[0] ^ consume, v[1], v[2], v[3]);
						break;

					case 1:
						state[lane_position] = Vector256.Create(v[0], v[1] ^ consume, v[2], v[3]);
						break;

					case 2:
						state[lane_position] = Vector256.Create(v[0], v[1], v[2] ^ consume, v[3]);
						break;

					case 3:
						state[lane_position] = Vector256.Create(v[0], v[1], v[2], v[3] ^ consume);
						break;
				}
#endif
				instance_position++;
			}
		}
	}
}
