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
		/// Add (in GC(2), using bitwise exclusive OR) the bytes of <paramref name="interleaved_data"/> to the state for all instances for <paramref name="length"/> bytes.
		/// </summary>
		/// <param name="interleaved_data">The interleaved data to consume</param>
		/// <param name="interleaved_data_offset">The offset, in bytes, from the start of <paramref name="interleaved_data"/> to start consuming bytes</param>
		/// <param name="length">The number of bytes of <paramref name="interleaved_data"/> to consume.</param>
		/// <returns>The number of bytes processed from <paramref name="interleaved_data"/></returns>
		/// <remarks>
		/// The interleaved data is structured as follows:
		/// A ulong (8 bytes) for instance 0, followed by a ulong (8 bytes) for instance 1, followed by a ulong (8 bytes) for instance 2, followed by a ulong (8 bytes) for instance 3, 
		/// and then the next 32 bytes for the next set of instances, repeating <see cref="lane_count"/> times
		/// </remarks>
		public int AddBlock(byte[] interleaved_data, int interleaved_data_offset, int length) {
			Vector256<ulong> v;
			int offset;

			offset = interleaved_data_offset;

			Debug.Assert(length >= 8 * parallelism * lane_count, "Not enough data for a whole block to process");

			for (int i = 0; i < lane_count; i++) {
				// Load the 4 sets of ulong data
				v = Vector256.LoadUnsafe(ref interleaved_data[offset]).AsUInt64();

				state[i] = Avx2.Xor(state[i], v);
				offset += parallelism * 8;    // 4 instances, 8 bytes each
			}

			return 8 * lane_count * parallelism;
		}
	}
}
