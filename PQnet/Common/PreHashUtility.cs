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

using System;

using PQnet.Digest;

namespace PQnet {
	internal class PreHashUtility {
		/// <summary>
		/// Calculate PHm and oid for pre-hash functions
		/// </summary>
		/// <param name="ph"></param>
		/// <param name="m"></param>
		/// <param name="oid"></param>
		/// <param name="ph_m"></param>
		/// <returns></returns>
		/// <exception cref="NotImplementedException"></exception>
		/// <exception cref="ArgumentException"></exception>
		internal static void GetPHm(PreHashFunction ph, byte[] m, out byte[] oid, out byte[] ph_m) {
			switch (ph) {
				case PreHashFunction.SHA224:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04 };
					throw new NotImplementedException("SHA224 Not yet implemented");

				case PreHashFunction.SHA256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01 };
#if !NET48
					ph_m = System.Security.Cryptography.SHA256.HashData(m);
#else
					using (System.Security.Cryptography.SHA256Cng SHA = new System.Security.Cryptography.SHA256Cng()) {
						ph_m = SHA.ComputeHash(m);
					}
#endif
					break;

				case PreHashFunction.SHA384:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02 };
#if !NET48
					ph_m = System.Security.Cryptography.SHA384.HashData(m);
#else
					using (System.Security.Cryptography.SHA384Cng SHA = new System.Security.Cryptography.SHA384Cng()) {
						ph_m = SHA.ComputeHash(m);
					}
#endif
					break;

				case PreHashFunction.SHA512:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03 };
#if !NET48
					ph_m = System.Security.Cryptography.SHA512.HashData(m);
#else
					using (System.Security.Cryptography.SHA512Cng SHA = new System.Security.Cryptography.SHA512Cng()) {
						ph_m = SHA.ComputeHash(m);
					}
#endif
					break;

				case PreHashFunction.SHA512_224:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x05 };
					throw new NotImplementedException("SHA512_224 Not yet implemented");

				case PreHashFunction.SHA512_256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x06 };
					throw new NotImplementedException("SHA512_256 Not yet implemented");

				case PreHashFunction.SHA3_224:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x07 };
					ph_m = Sha3_224.ComputeHash(m);
					break;

				case PreHashFunction.SHA3_256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x08 };
					ph_m = Sha3_256.ComputeHash(m);
					break;

				case PreHashFunction.SHA3_384:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x09 };
					ph_m = Sha3_384.ComputeHash(m);
					break;

				case PreHashFunction.SHA3_512:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0a };
					ph_m = Sha3_512.ComputeHash(m);
					break;

				case PreHashFunction.SHAKE128:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0B };
					ph_m = Shake128.HashData(m, 256 / 8);
					break;

				case PreHashFunction.SHAKE256:
					oid = new byte[] { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x0C };
					ph_m = Shake256.HashData(m, 512 / 8);
					break;

				default:
					throw new ArgumentException($"Invalid hash function '{ph}'");
			}
		}
	}
}
