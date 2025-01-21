// MIT License
// 
// Copyright (c) 2025 Peter Dennis Bartok 
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
using System.Text.RegularExpressions;

using PQnet.test.AVCP;

namespace PQnet.test {
	internal class RspFile {
		public class MonteCarlo {
			public class CountEntry {
				public CountEntry(int count, int output_len, string output) {
					Count = count;
					OutputLen = output_len;
					Output = output;
				}

				public int Count { get; set; }
				public int OutputLen { get; set; }
				public string Output { get; set; }
			}

			public MonteCarlo() {
				this.Counts = new List<CountEntry>();
			}

			public int MininumLength { get; set; }
			public int MaximumLength { get; set; }
			public string Msg { get; set; }

			public List<CountEntry> Counts { get; set; }
		}

		public class Hash {
			public class HashEntry {
				public HashEntry(int len, string msg, string output) {
					Len = len;
					Msg = msg;
					Output = output;
				}
				public int Len { get; set; }
				public string Msg { get; set; }
				public string Output { get; set; }
			}

			public Hash() {
				this.Entries = new List<HashEntry>();
			}
			public int OutputLen { get; set; }
			public List<HashEntry> Entries { get; set; }
		}


		public Hash HashRsp { get; set; }
		public MonteCarlo MonteCarloRsp { get; set; }


		private static Regex min_regex = new Regex(@"\[Minimum Output Length \(bits\)\s*=\s*(?<val>\d*)\]", RegexOptions.Multiline | RegexOptions.Compiled);
		private static Regex max_regex = new Regex(@"\[Maximum Output Length \(bits\)\s*=\s*(?<val>\d*)\]", RegexOptions.Multiline | RegexOptions.Compiled);
		private static Regex msg_regex = new Regex(@"(Msg|Seed)\s=\s(?<msg>[a-zA-Z0-9]*)", RegexOptions.Multiline | RegexOptions.Compiled);
		private static Regex counts_regex = new Regex(@"COUNT\s*=\s*(?<count>\d*).*(Outputlen\s*=\s*(?<outlen>\d*).*Output\s*=\s*(?<output>[a-fA-F0-9]*)|MD\s*=\s*(?<output>[a-fA-F0-9]*))", RegexOptions.Compiled);
		public static MonteCarlo LoadMonteCarlo(string resource) {
			byte[] file_data;
			string file_text;
			MonteCarlo result;
			MatchCollection matches;
			Match m;

			file_data = Utilities.LoadFile(resource);
			file_text = Encoding.ASCII.GetString(file_data);


			result = new MonteCarlo();

			m = min_regex.Match(file_text);
			if (m.Success) {
				result.MininumLength = int.Parse(m.Groups["val"].Value);
			}
			m = max_regex.Match(file_text);
			if (m.Success) {
				result.MaximumLength = int.Parse(m.Groups["val"].Value);
			}
			m = msg_regex.Match(file_text);
			if (m.Success) {
				result.Msg = m.Groups["msg"].Value;
			}

			// Horrible, but I'm lazy and it's only a test
			file_text = file_text.Replace('\n', ' ').Replace('\r', ' ').Replace("COUNT", "\r\nCOUNT");

			matches = counts_regex.Matches(file_text);
			foreach (Match match in matches) {
				result.Counts.Add(new MonteCarlo.CountEntry(
					int.Parse(match.Groups["count"].Value),
					int.Parse(match.Groups["outlen"].Success ? match.Groups["outlen"].Value : "0"),
					match.Groups["output"].Value
				));
			}

			return result;
		}

		private static Regex output_len_regex = new Regex(@"\[(Outputlen|L)\s*=\s*(?<val>\d*)\]", RegexOptions.Multiline | RegexOptions.Compiled);
		private static Regex test_regex = new Regex(@"Len\s*=\s*(?<len>\d*).*Msg\s*=\s*(?<msg>[a-fA-F0-9]*).*(Output|MD)\s*=\s*(?<output>[a-fA-F0-9]*)", RegexOptions.Compiled);
		public static Hash LoadHash(string resource) {
			byte[] file_data;
			string file_text;
			Hash result;
			MatchCollection matches;

			file_data = Utilities.LoadFile(resource);
			file_text = Encoding.ASCII.GetString(file_data);

			result = new Hash();

			result.OutputLen = int.Parse(output_len_regex.Match(file_text).Groups["val"].Value);

			// Horrible, but I'm lazy and it's only a test
			file_text = file_text.Replace('\n', ' ').Replace('\r', ' ').Replace("Len = ", "\r\nLen = ");

			matches = test_regex.Matches(file_text);
			foreach (Match match in matches) {
				result.Entries.Add(new Hash.HashEntry(
					int.Parse(match.Groups["len"].Value),
					match.Groups["msg"].Value,
					match.Groups["output"].Value
				));
			}

			return result;
		}
	}
}
