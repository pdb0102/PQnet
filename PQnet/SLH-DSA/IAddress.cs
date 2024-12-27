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
	/// FIPS 205 Section 4.3 ADRS Member Functions
	/// </summary>
	public interface IAddress {
		/// <summary>
		/// Clone the address
		/// </summary>
		/// <returns></returns>
		public IAddress Clone();

		/// <summary>
		/// The the layer value
		/// </summary>
		/// <param name="layer"></param>
		public void SetLayerAddress(uint layer);

		/// <summary>
		/// Set the tree value
		/// </summary>
		/// <param name="tree"></param>
		public void SetTreeAddress(ulong tree);

		/// <summary>
		/// Set the type and clear the rest of the address
		/// </summary>
		/// <param name="type"></param>
		public void SetTypeAndClear(AddressType type);

		/// <summary>
		/// Set the key pair value
		/// </summary>
		/// <param name="keyPair"></param>
		public void SetKeyPairAddress(uint keyPair);

		/// <summary>
		/// Set the chain value
		/// </summary>
		/// <param name="chain"></param>
		public void SetChainAddress(uint chain);

		/// <summary>
		/// Set the tree height
		/// </summary>
		/// <param name="treeHeight"></param>
		public void SetTreeHeight(uint treeHeight);

		/// <summary>
		/// Set the hash
		/// </summary>
		/// <param name="hash"></param>
		public void SetHashAddress(uint hash);

		/// <summary>
		/// Set the tree index
		/// </summary>
		/// <param name="treeIndex"></param>
		public void SetTreeIndex(uint treeIndex);

		/// <summary>
		/// Get the tree index
		/// </summary>
		public uint TreeIndex { get; }

		/// <summary>
		/// Get the key pair value
		/// </summary>
		public uint KeyPairAddress { get; }

		/// <summary>
		/// The the full address
		/// </summary>
		public byte[] Bytes { get; }
	}

}