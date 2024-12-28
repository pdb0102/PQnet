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
	/// FIPS 205 Section 11.2 ADRS Implementation for SHA2
	/// </summary>
	internal class Sha2Address : IAddress {
		private const int LayerOffset = 0;
		private const int TreeOffset = 1;
		private const int TypeOffset = 9;
		private const int KeyPairAddrOffset = 10;
		private const int ChainAddrOffset = 14;
		private const int HashAddrOffset = 18;
		private const int TreeHeightOffset = 14;
		private const int TreeIndexOffset = 18;

		private byte[] A;

		/// <summary>
		/// Instantiates a new object of class <see cref="Sha2Address"/> 
		/// </summary>
		public Sha2Address() {
			A = new byte[22];
		}

		/// <summary>
		/// ADRS[0:22]
		/// </summary>
		public byte[] Bytes {
			get {
				return A;
			}
		}

		/// <summary>
		/// 𝑖 ← toInt(ADRS[18 ∶ 22], 4)
		/// </summary>
		public uint TreeIndex {
			get {
				return Utility.toInt(A, TreeIndexOffset);
			}
		}

		/// <summary>
		/// 𝑖 ← toInt(ADRS[10 ∶ 14], 4)
		/// </summary>
		public uint KeyPairAddress {
			get {
				return Utility.toInt(A, KeyPairAddrOffset);
			}
		}

		/// <summary>
		/// Returns a clone of the current <see cref="Sha2Address"/>
		/// </summary>
		/// <returns>The cloned <see cref="Sha2Address"/></returns>
		public IAddress Clone() {
			Sha2Address clone;

			clone = new Sha2Address();
			Array.Copy(A, clone.A, A.Length);
			return clone;
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 14] ∥ toByte(𝑖, 4) ∥ ADRS[18 ∶ 22]
		/// </summary>
		/// <param name="chain"></param>
		public void SetChainAddress(uint chain) {
			Utility.toByte(chain, A, ChainAddrOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 18] ∥ toByte(𝑖, 4)
		/// </summary>
		/// <param name="hash"></param>
		public void SetHashAddress(uint hash) {
			Utility.toByte(hash, A, HashAddrOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 10] ∥ toByte(𝑖, 4) ∥ ADRS[14 ∶ 22]
		/// </summary>
		/// <param name="keyPair"></param>
		public void SetKeyPairAddress(uint keyPair) {
			Utility.toByte(keyPair, A, KeyPairAddrOffset);
		}

		/// <summary>
		/// ADRS ← toByte(𝑙, 1) ∥ ADRS[1 ∶ 22]
		/// </summary>
		/// <param name="layer"></param>
		public void SetLayerAddress(uint layer) {
			A[LayerOffset] = (byte)layer;
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 1] ∥ toByte(𝑡, 8) ∥ ADRS[9 ∶ 22]
		/// </summary>
		/// <param name="tree"></param>
		public void SetTreeAddress(ulong tree) {
			Utility.toByte(tree, A, TreeOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 14] ∥ toByte(𝑖, 4) ∥ ADRS[18 ∶ 22]
		/// </summary>
		/// <param name="treeHeight"></param>
		public void SetTreeHeight(uint treeHeight) {
			Utility.toByte(treeHeight, A, TreeHeightOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 18] ∥ toByte(𝑖, 4)
		/// </summary>
		/// <param name="treeIndex"></param>
		public void SetTreeIndex(uint treeIndex) {
			Utility.toByte(treeIndex, A, TreeIndexOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 9] ∥ toByte(𝑌 , 1) ∥ toByte(0, 12)
		/// </summary>
		/// <param name="type"></param>
		public void SetTypeAndClear(AddressType type) {
			A[TypeOffset] = (byte)type;
			Array.Clear(A, 10, 12);
		}
	}
}