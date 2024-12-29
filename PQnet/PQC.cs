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
	/// The <c>PQnet</c> namespace contains classes and methods for post-quantum cryptographic algorithms.
	/// </summary>
	static class NamespaceDoc { }

	/// <summary>
	/// Provides access to various post-quantum cryptographic algorithms.
	/// </summary>
	public static class PQC {
		private static MlKem512 ml_kem_512 = new MlKem512();
		private static MlKem768 ml_kem_768 = new MlKem768();
		private static MlKem1024 ml_kem_1024 = new MlKem1024();
		private static MlDsa44 ml_dsa_44 = new MlDsa44();
		private static MlDsa65 ml_dsa_65 = new MlDsa65();
		private static MlDsa87 ml_dsa_87 = new MlDsa87();
		private static SlhDsaShake_128f slh_dsa_shake_128f = new SlhDsaShake_128f();
		private static SlhDsaShake_128s slh_dsa_shake_128s = new SlhDsaShake_128s();
		private static SlhDsaShake_192f slh_dsa_shake_192f = new SlhDsaShake_192f();
		private static SlhDsaShake_192s slh_dsa_shake_192s = new SlhDsaShake_192s();
		private static SlhDsaShake_256f slh_dsa_shake_256f = new SlhDsaShake_256f();
		private static SlhDsaShake_256s slh_dsa_shake_256s = new SlhDsaShake_256s();
		private static SlhDsaSha2_128f slh_dsa_sha2_128f = new SlhDsaSha2_128f();
		private static SlhDsaSha2_128s slh_dsa_sha2_128s = new SlhDsaSha2_128s();
		private static SlhDsaSha2_192f slh_dsa_sha2_192f = new SlhDsaSha2_192f();
		private static SlhDsaSha2_192s slh_dsa_sha2_192s = new SlhDsaSha2_192s();
		private static SlhDsaSha2_256f slh_dsa_sha2_256f = new SlhDsaSha2_256f();
		private static SlhDsaSha2_256s slh_dsa_sha2_256s = new SlhDsaSha2_256s();

		/// <summary>
		/// Gets a ML-KEM-512 encapsulation scheme object.
		/// </summary>
		public static MlKem512 MlKem512 {
			get {
				return ml_kem_512;
			}
		}

		/// <summary>
		/// Gets a ML-KEM-768 encapsulation scheme object.
		/// </summary>
		public static MlKem768 MlKem768 {
			get {
				return ml_kem_768;
			}
		}

		/// <summary>
		/// Gets a ML-KEM-1024 encapsulation scheme object.
		/// </summary>
		public static MlKem1024 MlKem1024 {
			get {
				return ml_kem_1024;
			}
		}

		/// <summary>
		/// Gets a ML-DSA-44 signature scheme object.
		/// </summary>
		public static MlDsa44 MlDsa44 {
			get {
				return ml_dsa_44;
			}
		}

		/// <summary>
		/// Gets a ML-DSA-65 signature scheme object.
		/// </summary>
		public static MlDsa65 MlDsa65 {
			get {
				return ml_dsa_65;
			}
		}

		/// <summary>
		/// Gets a ML-DSA-87 signature scheme object.
		/// </summary>
		public static MlDsa87 MlDsa87 {
			get {
				return ml_dsa_87;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-128f signature scheme object.
		/// </summary>
		public static SlhDsaShake_128f SlhDsaShake_128f {
			get {
				return slh_dsa_shake_128f;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-128s signature scheme object.
		/// </summary>
		public static SlhDsaShake_128s SlhDsaShake_128s {
			get {
				return slh_dsa_shake_128s;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-192f signature scheme object.
		/// </summary>
		public static SlhDsaShake_192f SlhDsaShake_192f {
			get {
				return slh_dsa_shake_192f;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-192s signature scheme object.
		/// </summary>
		public static SlhDsaShake_192s SlhDsaShake_192s {
			get {
				return slh_dsa_shake_192s;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-256f signature scheme object.
		/// </summary>
		public static SlhDsaShake_256f SlhDsaShake_256f {
			get {
				return slh_dsa_shake_256f;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-256s signature scheme object.
		/// </summary>
		public static SlhDsaShake_256s SlhDsaShake_256s {
			get {
				return slh_dsa_shake_256s;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-128f signature scheme object.
		/// </summary>
		public static SlhDsaSha2_128f SlhDsaSha2_128f {
			get {
				return slh_dsa_sha2_128f;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-128s signature scheme object.
		/// </summary>
		public static SlhDsaSha2_128s SlhDsaSha2_128s {
			get {
				return slh_dsa_sha2_128s;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-192f signature scheme object.
		/// </summary>
		public static SlhDsaSha2_192f SlhDsaSha2_192f {
			get {
				return slh_dsa_sha2_192f;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-192s signature scheme object.
		/// </summary>
		public static SlhDsaSha2_192s SlhDsaSha2_192s {
			get {
				return slh_dsa_sha2_192s;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-256f signature scheme object.
		/// </summary>
		public static SlhDsaSha2_256f SlhDsaSha2_256f {
			get {
				return slh_dsa_sha2_256f;
			}
		}

		/// <summary>
		/// Gets a SLH-DSA-SHAKE-256s signature scheme object.
		/// </summary>
		public static SlhDsaSha2_256s SlhDsaSha2_256s {
			get {
				return slh_dsa_sha2_256s;
			}
		}

		/// <summary>
		/// Return a signature scheme object.
		/// </summary>
		/// <param name="name">The name of the signature algorithm</param>
		/// <returns>An <see cref="ISignature"/> representing the algorithm <paramref name="name"/></returns>
		public static ISignature GetSignatureAlgorithmInstance(string name) {
			switch (name.ToLower()) {
				case "44":
				case "mldsa44":
				case "mldsa-44":
				case "ml-dsa-44":
					return ml_dsa_44;

				case "65":
				case "mldsa65":
				case "mldsa-65":
				case "ml-dsa-65":
					return ml_dsa_65;

				case "87":
				case "mldsa87":
				case "mldsa-87":
				case "ml-dsa-87":
					return ml_dsa_87;

				case "slhdsashakesha2128f":
				case "slhdsasha2-128f":
				case "slhdsa-sha2-128f":
				case "slh-dsa-sha2-128f":
					return slh_dsa_sha2_128f;

				case "slhdsashakesha2128s":
				case "slhdsasha2-128s":
				case "slhdsa-sha2-128s":
				case "slh-dsa-sha2-128s":
					return slh_dsa_sha2_128s;

				case "slhdsashakesha2192f":
				case "slhdsasha2-192f":
				case "slhdsa-sha2-192f":
				case "slh-dsa-sha2-192f":
					return slh_dsa_sha2_192f;

				case "slhdsashakesha2192s":
				case "slhdsasha2-192s":
				case "slhdsa-sha2-192s":
				case "slh-dsa-sha2-192s":
					return slh_dsa_sha2_192s;

				case "slhdsashakesha2256f":
				case "slhdsasha2-256f":
				case "slhdsa-sha2-256f":
				case "slh-dsa-sha2-256f":
					return slh_dsa_sha2_256f;

				case "slhdsashakesha2256s":
				case "slhdsasha2-256s":
				case "slhdsa-sha2-256s":
				case "slh-dsa-sha2-256s":
					return slh_dsa_sha2_256s;

				case "slhdsashakeshake2128f":
				case "slhdsashake-128f":
				case "slhdsa-shake-128f":
				case "slh-dsa-shake-128f":
					return slh_dsa_shake_128f;

				case "slhdsashakeshake2128s":
				case "slhdsashake-128s":
				case "slhdsa-shake-128s":
				case "slh-dsa-shake-128s":
					return slh_dsa_shake_128s;

				case "slhdsashakeshake192f":
				case "slhdsashake-192f":
				case "slhdsa-shake-192f":
				case "slh-dsa-shake-192f":
					return slh_dsa_shake_192f;

				case "slhdsashakeshake192s":
				case "slhdsashake-192s":
				case "slhdsa-shake-192s":
				case "slh-dsa-shake-192s":
					return slh_dsa_shake_192s;

				case "slhdsashakeshake256f":
				case "slhdsashake-256f":
				case "slhdsa-shake-256f":
				case "slh-dsa-shake-256f":
					return slh_dsa_shake_256f;

				case "slhdsashakeshake256s":
				case "slhdsashake-256s":
				case "slhdsa-shake-256s":
				case "slh-dsa-shake-256s":
					return slh_dsa_shake_256s;

				default:
					return null;
			}
		}

		/// <summary>
		/// Return a encapsulation scheme object.
		/// </summary>
		/// <param name="name">The name of the encapsulation algorithm</param>
		/// <returns>An <see cref="IEncapsulate"/> representing the algorithm <paramref name="name"/></returns>
		public static IEncapsulate GetEncapsulationAlgorithmInstance(string name) {
			switch (name.ToLower()) {
				case "mlkem512":
				case "mlkem-512":
				case "ml-kem-512":
					return ml_kem_512;

				case "mlkem768":
				case "mlkem-768":
				case "ml-kem-768":
					return ml_kem_768;

				case "mlkem1024":
				case "mlkem-1024":
				case "ml-kem-1024":
					return ml_kem_1024;

				default:
					return null;
			}
		}
	}
}
