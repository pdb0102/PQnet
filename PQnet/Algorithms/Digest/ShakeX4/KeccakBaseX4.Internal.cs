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

using System;
using System.Runtime.Intrinsics;

namespace PQnet.Digest {
	public partial class KeccakBaseX4 {
		private const int parallelism = 4;
		private const int width = 1600;
		private const int lane_size = 8;    // bytes, sizeof(ulong)

		private int security;               // bits

		private int rate;                   // bits
		private int rate_in_bytes;
		private int rate_in_lanes;
		private int lane_count;
		private int capacity;
		private int capacity_in_bytes;
		private int capacity_in_lanes;
		private byte suffix;
		internal Vector256<ulong>[] state;  // internal for testing

#if DEBUGSTATE
		internal List<ulong[]> states0 = new List<ulong[]>();
		internal List<ulong[]> states1 = new List<ulong[]>();
		internal List<ulong[]> states2 = new List<ulong[]>();
		internal List<ulong[]> states3 = new List<ulong[]>();
#endif

		internal KeccakBaseX4() {
			state = new Vector256<ulong>[25];

			for (int i = 0; i < 25; i++) {
				state[i] = Vector256<ulong>.Zero;
			}
		}

		internal void Reset() {
			for (int i = 0; i < 25; i++) {
				state[i] = Vector256<ulong>.Zero;
			}
#if DEBUGSTATE
			states0 = new List<ulong[]>();
			states1 = new List<ulong[]>();
			states2 = new List<ulong[]>();
			states3 = new List<ulong[]>();
#endif
		}

		internal KeccakBaseX4(int rate_in_bytes, int security, byte suffix) : this() {
			this.rate_in_bytes = rate_in_bytes;
			this.security = security;
			this.suffix = suffix;


			this.rate = rate_in_bytes * 8;
			this.rate_in_lanes = rate_in_bytes / lane_size;
			this.lane_count = rate_in_bytes / lane_size;
			this.capacity = 2 * security;
			this.capacity_in_bytes = capacity / 8;
			this.capacity_in_lanes = capacity_in_bytes / lane_size;
		}

		internal bool Sponge(byte[] input1, byte[] input2, byte[] input3, byte[] input4, byte[] output1, byte[] output2, byte[] output3, byte[] output4, int output_length, int input_length = -1) {
			byte[] interleaved_data;
			int input_consumed;
			int input_left;
			int interleaved_input_left;
			int processed;
			int output_index;

			if (input_length == -1) {
				input_length = input1.Length;
			} else {
				if (input_length > input1.Length) {
					return false;
				}
			}

			if (input_length > input2.Length || input_length > input3.Length || input_length > input4.Length) {
				return false;
			}

			if (rate + capacity != width) {
				return false;
			}

			if ((rate > width) || ((rate % 8) != 0)) {
				return false;
			}
			if (suffix == 0) {
				return false;
			}

			input_consumed = 0;
			interleaved_input_left = input_length << 2; // * parallelism;

			interleaved_data = InterleaveArrays(input1, input2, input3, input4, input_length);

			if (((rate_in_bytes % (width / 200)) == 0) && (input_length >= rate_in_bytes)) {
				// Fast path
				processed = Fast_Block_Absorb(interleaved_data, interleaved_data.Length);
				interleaved_input_left -= processed;
				input_consumed += processed;
			}

			// Absorb the data in rate-sized chunks
			while (interleaved_input_left >= (rate_in_bytes << 2 /* * parallelism */)) {
				processed = AddBytesAll(interleaved_data, input_consumed, rate_in_bytes);
				PermuteAll_24rounds();
				interleaved_input_left -= processed;
				input_consumed += processed;
			}

			input_left = interleaved_input_left >> 2;// / parallelism;

			// Absorb the remaining data
			AddBytesAll(interleaved_data, input_consumed, input_left);

			// Absorb the suffix
			AddByteAll(input_left, suffix);

			// If the first bit of padding is at position rate- 1, we need a whole new block for the second bit of padding
			if ((suffix >= 0x80) && (input_left == (rate_in_bytes - 1))) {
				PermuteAll_24rounds();
			}
			AddByteAll(rate_in_bytes - 1, 0x80);

			PermuteAll_24rounds();

			// Start squeezing
			output_index = 0;

			while (output_length > rate_in_bytes) {
				output_index += ExtractBytesAll(output1, output2, output3, output4, output_index);
				PermuteAll_24rounds();
				output_length -= rate_in_bytes;
			}

			if (output_length > 0) {
				ExtractBytes(0, 0, output1, output_index, output_length);
				ExtractBytes(1, 0, output2, output_index, output_length);
				ExtractBytes(2, 0, output3, output_index, output_length);
				ExtractBytes(3, 0, output4, output_index, output_length);
			}

			return true;
		}

		/// <summary>
		/// Interleave four byte arrays into a single one for use by <see cref="KeccakBaseX4"/>
		/// </summary>
		/// <param name="input1">The first array</param>
		/// <param name="input2">The second array</param>
		/// <param name="input3">The third array</param>
		/// <param name="input4">The fourth array</param>
		/// <param name="input_length">The maximum bytes to take from the input</param>
		/// <returns>An interleaved array, with 8 bytes from the first input, 8 from the second, third and fourth, then the next 8 bytes from the first, and so on</returns>
		public static byte[] InterleaveArrays(byte[] input1, byte[] input2, byte[] input3, byte[] input4, int input_length = -1) {
			Span<byte> temp = stackalloc byte[16];
			Span<byte> span1;
			Span<byte> span2;
			Span<byte> span3;
			Span<byte> span4;
			Span<byte> resultSpan;
			Vector128<byte> v1;
			Vector128<byte> v2;
			Vector128<byte> v3;
			Vector128<byte> v4;
			int remaining;
			int maxLength;
			int paddedLength;
			int totalLength;
			byte[] result;


			if (input_length == -1) {
				maxLength = Math.Max(Math.Max(input1.Length, input2.Length), Math.Max(input3.Length, input4.Length));
			} else {
				maxLength = Math.Min(input_length, Math.Max(Math.Max(input1.Length, input2.Length), Math.Max(input3.Length, input4.Length)));
			}

			paddedLength = (maxLength + 7) & ~7; // Round up to the nearest multiple of 8
			totalLength = paddedLength * 4;
			result = new byte[totalLength];

			span1 = input1.AsSpan();
			span2 = input2.AsSpan();
			span3 = input3.AsSpan();
			span4 = input4.AsSpan();
			resultSpan = result.AsSpan();

			int resultIndex = 0;
			for (int i = 0; i < paddedLength; i += 8) {
				// Copy 8 bytes from each input array to the result array using SIMD
				remaining = maxLength - i;
				if (remaining >= 8) {
					v1 = Vector128.LoadUnsafe(ref span1[i]);
					v1.StoreUnsafe(ref resultSpan[resultIndex]);
				} else if (remaining > 0) {
					span1.Slice(i, remaining).CopyTo(temp);
					temp.Slice(remaining).Clear();
					v1 = Vector128.LoadUnsafe(ref temp[0]);
					v1.StoreUnsafe(ref resultSpan[resultIndex]);
				} else {
					resultSpan.Slice(resultIndex, 8).Clear();
				}
				resultIndex += 8;

				if (remaining >= 8) {
					v2 = Vector128.LoadUnsafe(ref span2[i]);
					v2.StoreUnsafe(ref resultSpan[resultIndex]);
				} else if (remaining > 0) {
					span2.Slice(i, remaining).CopyTo(temp);
					temp.Slice(remaining).Clear();
					v2 = Vector128.LoadUnsafe(ref temp[0]);
					v2.StoreUnsafe(ref resultSpan[resultIndex]);
				} else {
					resultSpan.Slice(resultIndex, 8).Clear();
				}
				resultIndex += 8;

				if (remaining >= 8) {
					v3 = Vector128.LoadUnsafe(ref span3[i]);
					v3.StoreUnsafe(ref resultSpan[resultIndex]);
				} else if (remaining > 0) {
					span3.Slice(i, remaining).CopyTo(temp);
					temp.Slice(remaining).Clear();
					v3 = Vector128.LoadUnsafe(ref temp[0]);
					v3.StoreUnsafe(ref resultSpan[resultIndex]);
				} else {
					resultSpan.Slice(resultIndex, 8).Clear();
				}
				resultIndex += 8;

				if (remaining >= 8) {
					v4 = Vector128.LoadUnsafe(ref span4[i]);
					v4.StoreUnsafe(ref resultSpan[resultIndex]);
				} else if (remaining > 0) {
					span4.Slice(i, remaining).CopyTo(temp);
					temp.Slice(remaining).Clear();
					v4 = Vector128.LoadUnsafe(ref temp[0]);
					v4.StoreUnsafe(ref resultSpan[resultIndex]);
				} else {
					resultSpan.Slice(resultIndex, 8).Clear();
				}
				resultIndex += 8;
			}

			return result;
		}

#if DEBUGSTATE
		internal void DumpState(int lane, out ulong[] states) {
			states = new ulong[25];

			for (int i = 0; i < 25; i++) {
				states[i] = state[i][lane];
			}
		}
#endif
	}
}