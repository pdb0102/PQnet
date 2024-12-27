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

namespace slhdsa;
public interface IHashAlgorithm {
	// FIPS 205 Section 4.1
	byte[] prf_msg(byte[] sk_prf, byte[] opt_rand, byte[] m);
	byte[] h_msg(byte[] r, byte[] pk_seed, byte[] pk_root, byte[] m);
	byte[] prf(byte[] pk_seed, byte[] sk_seed, IAddress adrs);
	byte[] t_len(byte[] pk_seed, IAddress adrs, byte[] m_l);
	byte[] h(byte[] pb_seed, IAddress adrs, byte[] m_2);
	byte[] f(byte[] pk_seed, IAddress adrs, byte[] m_1);
	string Name { get; }
	bool is_shake { get; }
}
