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
	/// FIPS 205 Section 4.1 - Hash Functions and Pseudo-Random Functions
	/// </summary>
	public interface IHashAlgorithm {
		/// <summary>
		/// A pseudorandom function (PRF) that generates the randomizer(𝑅) for the randomized hashing of the message to be signed.
		/// </summary>
		/// <param name="sk_prf"></param>
		/// <param name="opt_rand"></param>
		/// <param name="m"></param>
		/// <returns></returns>
		byte[] prf_msg(byte[] sk_prf, byte[] opt_rand, byte[] m);

		/// <summary>
		/// Used to generate the digest of the message to be signed.
		/// </summary>
		/// <param name="r"></param>
		/// <param name="pk_seed"></param>
		/// <param name="pk_root"></param>
		/// <param name="m"></param>
		/// <returns></returns>
		byte[] h_msg(byte[] r, byte[] pk_seed, byte[] pk_root, byte[] m);

		/// <summary>
		/// A PRF that is used to generate the secret values in WOTS+ and FORS private keys.
		/// </summary>
		/// <param name="pk_seed"></param>
		/// <param name="sk_seed"></param>
		/// <param name="adrs"></param>
		/// <returns></returns>
		byte[] prf(byte[] pk_seed, byte[] sk_seed, IAddress adrs);

		/// <summary>
		/// A hash function that maps an ℓ𝑛-byte message to an 𝑛-byte message.
		/// </summary>
		/// <param name="pk_seed"></param>
		/// <param name="adrs"></param>
		/// <param name="m_l"></param>
		/// <returns></returns>
		byte[] t_len(byte[] pk_seed, IAddress adrs, byte[] m_l);

		/// <summary>
		/// A special case of Tℓ that takes a 2𝑛-byte message as input.
		/// </summary>
		/// <param name="pk_seed"></param>
		/// <param name="adrs"></param>
		/// <param name="m_2"></param>
		/// <returns></returns>
		byte[] h(byte[] pk_seed, IAddress adrs, byte[] m_2);

		/// <summary>
		/// A hash function that takes an 𝑛-byte message as input and produces an 𝑛-byte output.
		/// </summary>
		/// <param name="pk_seed"></param>
		/// <param name="adrs"></param>
		/// <param name="m_1"></param>
		/// <returns></returns>
		byte[] f(byte[] pk_seed, IAddress adrs, byte[] m_1);

		/// <summary>
		/// Gets the name of the hash algorithm.
		/// </summary>
		string Name { get; }

		/// <summary>
		/// Gets a value indicating whether the hash algorithm is a SHAKE function.
		/// </summary>
		bool IsShake { get; }
	}
}