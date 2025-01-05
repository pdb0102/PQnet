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

namespace PQnet.Digest {
	public partial class ShakeX4 {
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

		internal ShakeX4() {
			state = new Vector256<ulong>[25];

			for (int i = 0; i < 25; i++) {
				state[i] = Vector256<ulong>.Zero;
			}
		}

		internal void Reset() {
			for (int i = 0; i < 25; i++) {
				state[i] = Vector256<ulong>.Zero;
			}
		}

		internal ShakeX4(int rate_in_bytes, int security, byte suffix) : this() {
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

		internal bool Sponge(byte[] input1, byte[] input2, byte[] input3, byte[] input4, byte[] output1, byte[] output2, byte[] output3, byte[] output4, int output_length) {
			byte[] interleaved_data;
			int input_consumed;
			int input_left;
			int processed;
			int output_index;

			if (input1.Length != input2.Length || input1.Length != input3.Length || input1.Length != input4.Length) {
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
			input_left = input1.Length;

			interleaved_data = CombineArrays(input1, input2, input3, input4);

			if (((rate_in_bytes % (width / 200)) == 0) && (input1.Length >= rate_in_bytes)) {
				// Fast path
				processed = Fast_Block_Absorb(interleaved_data, interleaved_data.Length);
				input_left -= processed;
				input_consumed += processed;
			}

			// Absorb the data in rate-sized chunks
			while (input_left >= rate_in_bytes) {
				processed = AddBytesAll(interleaved_data, input_consumed, rate_in_bytes);
				PermuteAll_24rounds();
				input_left -= processed;
				input_consumed += processed;
			}

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
				output_index += ExtractBytesAll(output1, output2, output3, output4);
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

		private static byte[] CombineArrays(byte[] input1, byte[] input2, byte[] input3, byte[] input4) {
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
			int remaining1;
			int remaining2;
			int remaining3;
			int remaining4;
			int maxLength;
			int paddedLength;
			int totalLength;
			byte[] result;


			maxLength = Math.Max(Math.Max(input1.Length, input2.Length), Math.Max(input3.Length, input4.Length));
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
				remaining1 = span1.Length - i;
				if (remaining1 >= 8) {
					v1 = Vector128.LoadUnsafe(ref span1[i]);
					v1.StoreUnsafe(ref resultSpan[resultIndex]);
				} else if (remaining1 > 0) {
					span1.Slice(i, remaining1).CopyTo(temp);
					temp.Slice(remaining1).Clear();
					v1 = Vector128.LoadUnsafe(ref temp[0]);
					v1.StoreUnsafe(ref resultSpan[resultIndex]);
				} else {
					resultSpan.Slice(resultIndex, 8).Clear();
				}
				resultIndex += 8;

				remaining2 = span2.Length - i;
				if (remaining2 >= 8) {
					v2 = Vector128.LoadUnsafe(ref span2[i]);
					v2.StoreUnsafe(ref resultSpan[resultIndex]);
				} else if (remaining2 > 0) {
					span2.Slice(i, remaining2).CopyTo(temp);
					temp.Slice(remaining2).Clear();
					v2 = Vector128.LoadUnsafe(ref temp[0]);
					v2.StoreUnsafe(ref resultSpan[resultIndex]);
				} else {
					resultSpan.Slice(resultIndex, 8).Clear();
				}
				resultIndex += 8;

				remaining3 = span3.Length - i;
				if (remaining3 >= 8) {
					v3 = Vector128.LoadUnsafe(ref span3[i]);
					v3.StoreUnsafe(ref resultSpan[resultIndex]);
				} else if (remaining3 > 0) {
					span3.Slice(i, remaining3).CopyTo(temp);
					temp.Slice(remaining3).Clear();
					v3 = Vector128.LoadUnsafe(ref temp[0]);
					v3.StoreUnsafe(ref resultSpan[resultIndex]);
				} else {
					resultSpan.Slice(resultIndex, 8).Clear();
				}
				resultIndex += 8;

				remaining4 = span4.Length - i;
				if (remaining4 >= 8) {
					v4 = Vector128.LoadUnsafe(ref span4[i]);
					v4.StoreUnsafe(ref resultSpan[resultIndex]);
				} else if (remaining4 > 0) {
					span4.Slice(i, remaining4).CopyTo(temp);
					temp.Slice(remaining4).Clear();
					v4 = Vector128.LoadUnsafe(ref temp[0]);
					v4.StoreUnsafe(ref resultSpan[resultIndex]);
				} else {
					resultSpan.Slice(resultIndex, 8).Clear();
				}
				resultIndex += 8;
			}

			return result;
		}

	}
}