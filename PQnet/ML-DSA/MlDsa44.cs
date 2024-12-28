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

// Ported from the reference implementation found at https://www.pq-crystals.org/dilithium/

namespace PQnet {
	/// <summary>
	/// Implements the ML-DSA-44 signature scheme.
	/// </summary>
	public class MlDsa44 : MlDsaBase {
		private bool deterministic;

		/// <summary>
		/// Creates a new instance of the <see cref="MlDsa44"/> class with non-deterministic signatures.
		/// </summary>
		public MlDsa44() : this(false) {
		}


		/// <summary>
		/// Creates a new instance of the <see cref="MlDsa44"/> class.
		/// </summary>
		/// <param name="deterministic"><c>true</c> if generated signatures should be deterministic, <c>false</c> otherwise</param>
		public MlDsa44(bool deterministic) : base(4, 4, 2, 39, 78, 1 << 17, (8380417 - 1) / 88, 80, 32) {
			this.deterministic = deterministic;
		}

		/// <inheritdoc/>
		public override bool Deterministic {
			get {
				return deterministic;
			}
		}

		/// <inheritdoc/>
		public override int NistSecurityCategory {
			get {
				return 2;
			}
		}
	}
}