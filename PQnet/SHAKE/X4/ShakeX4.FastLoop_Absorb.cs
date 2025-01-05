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

namespace PQnet.Digest {
	public partial class ShakeX4 {
		/// <summary>
		/// Loads 4 lanes of the state with the interleaved data, and permutes the state.
		/// </summary>
		/// <param name="interleaved_data">The interleaved data to consume</param>
		/// <param name="length">The number of bytes to consume from <paramref name="interleaved_data"/></param>
		/// <returns>The number of consumed bytes</returns>
		/// <remarks>
		/// The interleaved data is structured as follows:
		/// A ulong (8 bytes) for instance 0, followed by a ulong (8 bytes) for instance 1, followed by a ulong (8 bytes) for instance 2, followed by a ulong (8 bytes) for instance 3, 
		/// and then the next 32 bytes for the next set of instances, repeating <see cref="lane_count"/> times
		/// </remarks>
		internal int Fast_Block_Absorb(byte[] interleaved_data, int length) {
			if (lane_count == 21) {
				// FIXME
				return -1;
			} else {
				int processed_bytes;
				int data_left;

				processed_bytes = 0;
				data_left = length;
				while (data_left >= lane_count * parallelism * 8) {
					processed_bytes += AddBlock(interleaved_data, processed_bytes, lane_count * parallelism * 8);
					PermuteAll_24rounds();
					data_left -= lane_count * parallelism * 8;
				}
				return processed_bytes;
			}
		}

	}
}
