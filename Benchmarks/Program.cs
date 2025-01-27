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

		private static void Measure(string test_name, Action action, int count = 3) {
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

		static void Main(string[] args) {
			Measure("Native SHA2-256", () => { System.Security.Cryptography.SHA256.HashData(hash_data); });
			Measure("PQNet SHA2-256", () => { byte[] out_buf; out_buf = new byte[32]; PQnet.Digest.Sha256.sha256(out_buf, hash_data, hash_data.Length); });

			Measure("Native SHA2-512", () => { System.Security.Cryptography.SHA512.HashData(hash_data); });
			Measure("PQNet SHA2-512", () => { byte[] out_buf; out_buf = new byte[64]; PQnet.Digest.Sha512.sha512(out_buf, hash_data, hash_data.Length); });
		}

	}
}