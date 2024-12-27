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

namespace PQnet.SLH_DSA {
	/// <summary>
	/// Implements the SLH-DSA-SHA2-192s signature scheme.
	/// </summary>
	public class SlhDsaSha2_192s : SlhDsaBase {
		/// <summary>
		/// Instantiates a new <see cref="SlhDsaSha2_192s"/> object with non-deterministic signatures.
		/// </summary>
		public SlhDsaSha2_192s() : this(false) {
		}

		/// <summary>
		/// Instantiates a new <see cref="SlhDsaSha2_192s"/> object.
		/// </summary>
		/// <param name="deterministic"><c>true</c> if generated signatures should be deterministic, <c>false</c> otherwise</param>
		public SlhDsaSha2_192s(bool deterministic) : base(new Sha2SecCat35Hash(24, 39), 24, 63, 7, 9, 14, 17, 4, 39) {
			Deterministic = deterministic;
		}

		/// <inheritdoc/>
		public override string Name {
			get {
				return "SLH-DSA-SHA2-192s";
			}
		}

		/// <inheritdoc/>
		public override int NistSecurityCategory {
			get {
				return 3;
			}
		}
	}
}
