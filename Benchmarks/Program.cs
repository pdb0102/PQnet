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
using System.Text;

namespace PQnet.Benchmarks {
	internal class Program {
		private static byte[] hash_data = Encoding.ASCII.GetBytes("01234567890123456789012345678901");

		private static void Measure(string test_name, Action action, int count = 300000) {
			Stopwatch stopwatch;

			// First run we throw away to warm up the JIT
			stopwatch = Stopwatch.StartNew();
			action();

			stopwatch.Reset();
			for (int i = 0; i < count; i++) {
				stopwatch.Start();
				action();
				stopwatch.Stop();
			}

			Console.WriteLine($"{test_name}: {stopwatch.ElapsedMilliseconds / count}ms [{stopwatch.ElapsedTicks / count} ticks]");
		}

		private static void Compare(string test_name, Func<byte[]> native_action, Func<byte[]> pqnet_action, int count = 3000) {
			byte[] action_result;
			byte[] expected_result;
			Stopwatch stopwatch;
			long native_ms = 0;
			long pqnet_ms = 0;
			long native_ticks = 0;
			long pqnet_ticks = 0;

			stopwatch = Stopwatch.StartNew();

			// First run we throw away to warm up the JIT
			expected_result = native_action();
			action_result = pqnet_action();

			if (action_result.Length != action_result.Length) {
				Console.WriteLine($"{test_name}: Length mismatch");
				return;
			}
			for (int x = 0; x < action_result.Length; x++) {
				if (action_result[x] != action_result[x]) {
					Console.WriteLine($"{test_name}: Mismatch");
					return;
				}
			}

			stopwatch.Reset();
			for (int i = 0; i < count; i++) {
				stopwatch.Start();
				native_action();
				stopwatch.Stop();
			}
			native_ms = stopwatch.ElapsedMilliseconds;
			native_ticks = stopwatch.ElapsedTicks;

			stopwatch.Reset();
			for (int i = 0; i < count; i++) {
				stopwatch.Start();
				pqnet_action();
				stopwatch.Stop();
			}
			pqnet_ms = stopwatch.ElapsedMilliseconds;
			pqnet_ticks = stopwatch.ElapsedTicks;

			if (native_ticks >= pqnet_ticks) {
				Console.WriteLine($"{test_name} [x{count:N0}]: PQNet is {(native_ms - pqnet_ms)}ms faster [{(native_ticks - pqnet_ticks):N0} ticks faster]");
			} else {
				Console.WriteLine($"{test_name} [x{count:N0}]: Native is {(pqnet_ms - native_ms)}ms faster [{(pqnet_ticks - native_ticks):N0} ticks faster]");
			}
		}

		static void Main(string[] args) {
			byte[] expected;

			Measure("Native SHA-256", () => { System.Security.Cryptography.SHA256.HashData(hash_data); });
			Measure("PQNet SHA-256", () => { byte[] out_buf; out_buf = new byte[32]; PQnet.Digest.Sha256.sha256(out_buf, hash_data, hash_data.Length); });

			expected = System.Security.Cryptography.SHA256.HashData(hash_data);
			Compare("SHA2-256", () => { return System.Security.Cryptography.SHA256.HashData(hash_data); }, () => { byte[] out_buf; out_buf = new byte[32]; PQnet.Digest.Sha256.sha256(out_buf, hash_data, hash_data.Length); return out_buf; });

			expected = System.Security.Cryptography.SHA256.HashData(hash_data);
			Compare("SHA2-512", () => { return System.Security.Cryptography.SHA512.HashData(hash_data); }, () => { byte[] out_buf; out_buf = new byte[64]; PQnet.Digest.Sha512.sha512(out_buf, hash_data, hash_data.Length); return out_buf; });

			if (System.Security.Cryptography.Shake128.IsSupported) {
				Console.WriteLine("Shake128 is supported by .Net");

				Compare("SHAKE-128", () => { return System.Security.Cryptography.Shake128.HashData(hash_data, 64); }, () => { return PQnet.Digest.Shake128.HashData(hash_data, 64); });
			}

			if (System.Security.Cryptography.Shake256.IsSupported) {
				Console.WriteLine("Shake256 is supported by .Net");

				Compare("SHAKE-256", () => { return System.Security.Cryptography.Shake256.HashData(hash_data, 64); }, () => { return PQnet.Digest.Shake256.HashData(hash_data, 64); });
			}
		}

	}
}