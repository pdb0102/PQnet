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

using System.Runtime.CompilerServices;

namespace PQnet.Digest {
	public partial class KeccakBaseX4 {
		internal void ExtractBytes(int instance, int state_offset, byte[] output, int output_offset, int length) {
			int lane_position;
			int output_index;

			output_index = output_offset;

#if true
			while (state_offset % 8 != 0) {
				// Consume enough bytes to be aligned on an 8-byte boundary so we can do whole chunks below
				output[output_index++] = ExtractByte(instance, state_offset++);
				length--;
			}
#else
			// FIXME measure if this is faster than the above
			int unaligned;

			unaligned = state_offset % 8;
			if (unaligned != 0) {
				// Consume enough bytes to be aligned on an 8-byte boundary so we can do whole chunks below
				for (int i = 0; i < unaligned; i++) {
					output[output_index++] = KeccakP1600times4_ExtractByte(instance, state_offset++);
					length--;
				}
			}
#endif

			lane_position = state_offset / 8;
			while (length >= 8) {
				Span<byte> span;

				span = output.AsSpan(output_index, sizeof(ulong));
				Unsafe.WriteUnaligned(ref span[0], state[lane_position][instance]);
				output_index += 8;
				length -= 8;
				lane_position++;
			}

			// Shortcut out of here if possible
			if (length == 0) {
				return;
			}

			state_offset = lane_position * 8;
			while (length > 0) {
				// Consume enough bytes to be aligned on an 8-byte boundary so we can do whole chunks below
				output[output_index++] = ExtractByte(instance, state_offset++);
				length--;
			}
		}

		[MethodImpl(MethodImplOptions.AggressiveInlining)]
		private byte ExtractByte(int instance, int state_offset) {
			int lane_position;
			ulong v;

			lane_position = state_offset / 8;
			v = state[lane_position][instance];

			return (byte)((v >> ((state_offset & 7) << 3)) & 0xff); // (byte)(ulong)(v >> ((state_offset % 8) * 8))
		}
	}
}
