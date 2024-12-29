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

namespace PQnet {
	/// <summary>
	/// Base class for ML-KEM key encapsulation algorithms.
	/// </summary>
	public abstract partial class MlKemBase {
		// private int k;
		// private int eta_1;
		// private int eta_2;
		// private int du;
		// private int dv;

		private int KYBER_K;
		private int KYBER_ETA1;
		private int KYBER_ETA2;

		private int KYBER_N = 256;
		private int KYBER_Q = 3329;

		private int KYBER_SYMBYTES = 32;
		private int KYBER_SSBYTES = 32;

		private int KYBER_POLYBYTES = 384;

		private int KYBER_INDCPA_MSGBYTES;
		private int KYBER_INDCPA_PUBLICKEYBYTES;
		private int KYBER_INDCPA_SECRETKEYBYTES;
		private int KYBER_INDCPA_BYTES;

		private int KYBER_POLYVECBYTES;
		private int KYBER_POLYCOMPRESSEDBYTES;
		private int KYBER_POLYVECCOMPRESSEDBYTES;

		private int KYBER_PUBLICKEYBYTES;
		private int KYBER_SECRETKEYBYTES;
		private int KYBER_CIPHERTEXTBYTES;


		/// <summary>
		/// Initializes a new instance of the <see cref="MlKemBase"/> class.
		/// </summary>
		/// <param name="k"></param>
		/// <param name="eta_1"></param>
		/// <param name="eta_2"></param>
		/// <param name="poly_compressed_bytes"></param>
		/// <param name="polyvec_compressed_bytes"></param>
		public MlKemBase(int k, int eta_1, int eta_2, int poly_compressed_bytes, int polyvec_compressed_bytes) {
			this.KYBER_K = k;
			this.KYBER_ETA1 = eta_1;
			this.KYBER_ETA2 = eta_2;

			KYBER_POLYCOMPRESSEDBYTES = poly_compressed_bytes;
			KYBER_POLYVECCOMPRESSEDBYTES = polyvec_compressed_bytes;

			KYBER_POLYVECBYTES = KYBER_K * KYBER_POLYBYTES;

			KYBER_INDCPA_MSGBYTES = KYBER_SYMBYTES;
			KYBER_INDCPA_PUBLICKEYBYTES = KYBER_POLYVECBYTES + KYBER_SYMBYTES;
			KYBER_INDCPA_SECRETKEYBYTES = KYBER_POLYVECBYTES;
			KYBER_INDCPA_BYTES = KYBER_POLYVECCOMPRESSEDBYTES + KYBER_POLYCOMPRESSEDBYTES;

			KYBER_PUBLICKEYBYTES = KYBER_INDCPA_PUBLICKEYBYTES;
			KYBER_SECRETKEYBYTES = KYBER_INDCPA_SECRETKEYBYTES + KYBER_INDCPA_PUBLICKEYBYTES + (2 * KYBER_SYMBYTES);
			KYBER_CIPHERTEXTBYTES = KYBER_INDCPA_BYTES;

		}

		/// <inheritdoc/>
		public abstract int NistSecurityCategory { get; }

		/// <summary>
		/// Gets the size, in bytes, of the private key
		/// </summary>
		public int PrivateKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the public key
		/// </summary>
		public int PublicKeyBytes { get; }

		/// <summary>
		/// Gets the size, in bytes, of the seed used for key generation
		/// </summary>
		public int SeedBytes {
			get {
				return 32;
			}
		}
	}
}
