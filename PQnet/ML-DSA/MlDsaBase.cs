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

using PQnet.Common;

namespace PQnet.ML_DSA {
	public abstract partial class MlDsaBase : ISecurityCategory {
		private int SeedBytes = 32;
		private int CrhBytes = 64;
		private int TrBytes = 64;
		private int RndBytes = 32;
		private int N = 256;
		private int Q = 8380417;
		private int D = 13;
		//private int RootOfUnity = 1753;
		private int PolyT1PackedBytes = 320;
		private int PolyT0PackedBytes = 416;
		private int PolyVecHPacketBytes;
		private int PolyZPackedBytes;
		private int PolyW1PackedBytes;
		private int PolyEtaPackedBytes;
		private int PublicKeybytes;
		private int SecretKeyBytes;
		private int SignatureBytes;

		private int K;
		private int L;
		private int Eta;
		private int Tau;
		private int Beta;
		private int Gamma1;
		private int Gamma2;
		private int Omega;
		private int CTildeBytes;

		public MlDsaBase(int K, int L, int Eta, int Tau, int Beta, int Gamma1, int Gamma2, int Omega, int CTildeBytes) {
			this.K = K;
			this.L = L;
			this.Eta = Eta;
			this.Tau = Tau;
			this.Beta = Beta;
			this.Gamma1 = Gamma1;
			this.Gamma2 = Gamma2;
			this.Omega = Omega;
			this.CTildeBytes = CTildeBytes;

			this.PolyVecHPacketBytes = Omega + K;
			if (Gamma1 == (1 << 17)) {
				PolyZPackedBytes = 576;
			} else if (Gamma1 == (1 << 19)) {
				PolyZPackedBytes = 640;
			} else {
				throw new NotImplementedException($"Unsupported Gamma1 value {Gamma1} [Allowed are '1 << 17' and '1 << 19']");
			}

			if (Gamma2 == (Q - 1) / 88) {
				PolyW1PackedBytes = 192;
			} else if (Gamma2 == (Q - 1) / 32) {
				PolyW1PackedBytes = 128;
			} else {
				throw new NotImplementedException($"Unsupported Gamma2 value {Gamma2} [Allowed are '(Q - 1) / 88' and '(Q - 1) / 32']");
			}

			if (Eta == 2) {
				PolyEtaPackedBytes = 96;
			} else if (Eta == 4) {
				PolyEtaPackedBytes = 128;
			} else {
				throw new NotImplementedException($"Unsupported Eta value {Eta} [Allowed are '2' and '4']");
			}

			PublicKeybytes = SeedBytes + (K * PolyT1PackedBytes);
			SecretKeyBytes = (2 * SeedBytes) + TrBytes + (L * PolyEtaPackedBytes) + (K * PolyEtaPackedBytes) + (K * PolyT0PackedBytes);
			SignatureBytes = CTildeBytes + (L * PolyZPackedBytes) + PolyVecHPacketBytes;

		}

		/// <summary>
		/// Gets whether the signature should be randomized or deterministic (predictable, same input causes same signature)
		/// </summary>
		public abstract bool Deterministic { get; }

		/// <inheritdoc/>
		public abstract int NistSecurityCategory { get; }
	}
}