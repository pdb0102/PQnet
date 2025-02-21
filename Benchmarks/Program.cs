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

using System.Text;

using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Jobs;
using BenchmarkDotNet.Running;

namespace PQnet.Benchmarks {
	[RPlotExporter]
	[SimpleJob(RuntimeMoniker.Net481)]
	[SimpleJob(RuntimeMoniker.Net90)]
	public class NativeVsPQNet {
		private byte[] test_data;

		[GlobalSetup]
		public void Setup() {
			test_data = Encoding.UTF8.GetBytes("test");
		}

		[Benchmark]
		public byte[] NativeSha256() {
#if !NET48
			return System.Security.Cryptography.SHA256.HashData(test_data);
#else
			return System.Security.Cryptography.SHA256.Create().ComputeHash(test_data);
#endif
		}

		[Benchmark]
		public byte[] PQNetSha256() {
			byte[] out_buf = new byte[32];
			PQnet.Digest.Sha256.sha256(out_buf, test_data, test_data.Length);
			return out_buf;
		}
	}

	internal class Program {

		static void Main(string[] args) => BenchmarkSwitcher.FromAssemblies(new[] { typeof(NativeVsPQNet).Assembly }).Run(args);
#if not
		static void Main(string[] args) {
			Summary summary;


			summary = BenchmarkRunner.Run<NativeVsPQNet>();
		}
#endif
	}
}