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
using System.Runtime.Intrinsics;
using System.Runtime.Intrinsics.X86;

namespace PQnet.Digest {
	public partial class KeccakBaseX4 {
		/// <summary>
		/// Add <paramref name="length"/> bytes from <paramref name="interleaved_data"/> to the state.
		/// </summary>
		/// <param name="interleaved_data"></param>
		/// <param name="interleaved_data_offset"></param>
		/// <param name="length"></param>
		/// <returns>The number of consumed bytes</returns>
		/// <remarks>
		/// This method should not be called if length is a whole block or more.
		/// </remarks>
		internal int AddBytesAll(byte[] interleaved_data, int interleaved_data_offset, int length) {
			Vector256<ulong> v;
			int offset;
			int lane;

			offset = interleaved_data_offset;

			Debug.Assert(length < 8 * parallelism * lane_count, "Should not call this method for a whole block");
			Debug.Assert(length >= parallelism * length / 32, "Not enough data for a whole lane to process");

			lane = 0;

			// Interleaved data is 4 sets of 8 bytes each even if the input was partial
			while (length > 0) {
				// Load the 4 sets of ulong data
				v = Vector256.LoadUnsafe(ref interleaved_data[offset]).AsUInt64();

				state[lane] = Avx2.Xor(state[lane], v);
				offset += parallelism * 8;    // 4 instances, 8 bytes each
				lane++;
				length -= 8;
			}

			return lane * 8 * parallelism;
		}
	}
}