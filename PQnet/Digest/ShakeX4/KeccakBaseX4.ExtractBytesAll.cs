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
using System.Runtime.CompilerServices;

namespace PQnet.Digest {
	public partial class KeccakBaseX4 {
		/// <summary>
		/// Retrieve all states for all lanes
		/// </summary>
		/// <param name="output1">Buffer for output of the the first instance</param>
		/// <param name="output2">Buffer for output of the the second instance</param>
		/// <param name="output3">Buffer for output of the the third instance</param>
		/// <param name="output4">Buffer for output of the the fourth instance</param>
		/// <param name="output_offset">The offset into ouputx to start writing the extracted bytes</param>
		internal int ExtractBytesAll(byte[] output1, byte[] output2, byte[] output3, byte[] output4, int output_offset) {
			Span<byte> span1;
			Span<byte> span2;
			Span<byte> span3;
			Span<byte> span4;
			int output_length;

			Debug.Assert(output1.Length >= rate_in_bytes, "Output array too small");
			Debug.Assert((output1.Length == output2.Length) && (output1.Length == output3.Length) && (output1.Length == output3.Length), "Output arrays not same size");

			output_length = 0;

			span1 = output1.AsSpan();
			span2 = output2.AsSpan();
			span3 = output3.AsSpan();
			span4 = output4.AsSpan();
			for (int i = 0; i < lane_count; i++) {
				Unsafe.WriteUnaligned(ref span1[output_offset + (i << 3)], state[i][0]);
				Unsafe.WriteUnaligned(ref span2[output_offset + (i << 3)], state[i][1]);
				Unsafe.WriteUnaligned(ref span3[output_offset + (i << 3)], state[i][2]);
				Unsafe.WriteUnaligned(ref span4[output_offset + (i << 3)], state[i][3]);
				output_length += 8;
			}

			return output_length;
		}
	}
}
