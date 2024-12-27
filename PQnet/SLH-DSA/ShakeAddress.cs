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
	/// FIPS 205 Section 4.3 ADRS Implement for SHAKE
	/// </summary>
	internal class ShakeAddress : IAddress {
		private const int LayerOffset = 0;
		private const int TreeOffset = 4;
		private const int TypeOffset = 16;
		private const int KeyPairAddrOffset = 20;
		private const int ChainAddrOffset = 24;
		private const int HashAddrOffset = 28;
		private const int TreeHeightOffset = 24;
		private const int TreeIndexOffset = 28;

		private byte[] A;

		/// <summary>
		/// Instantiates a new object of class <see cref="Sha2Address"/>
		/// </summary>
		public ShakeAddress() {
			A = new byte[32];
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
		/// 𝑖 ← toInt(ADRS[28 ∶ 32], 4)
		/// </summary>
		public uint TreeIndex {
			get {
				return Utility.toInt(A, TreeIndexOffset);
			}
		}

		/// <summary>
		/// 𝑖 ← toInt(ADRS[20 ∶ 24], 4)
		/// </summary>
		public uint KeyPairAddress {
			get {
				return Utility.toInt(A, KeyPairAddrOffset);
			}
		}

		public IAddress Clone() {
			ShakeAddress clone;

			clone = new ShakeAddress();
			Array.Copy(A, clone.A, A.Length);
			return clone;
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
		/// </summary>
		/// <param name="chain"></param>
		public void SetChainAddress(uint chain) {
			Utility.toByte(chain, A, ChainAddrOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
		/// </summary>
		/// <param name="hash"></param>
		public void SetHashAddress(uint hash) {
			Utility.toByte(hash, A, HashAddrOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 20] ∥ toByte(𝑖, 4) ∥ ADRS[24 ∶ 32]
		/// </summary>
		/// <param name="keyPair"></param>
		public void SetKeyPairAddress(uint keyPair) {
			Utility.toByte(keyPair, A, KeyPairAddrOffset);
		}

		/// <summary>
		/// ADRS ← toByte(𝑙, 4) ∥ ADRS[4 ∶ 32]
		/// </summary>
		/// <param name="layer"></param>
		public void SetLayerAddress(uint layer) {
			Utility.toByte(layer, A, LayerOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 4] ∥ toByte(𝑡, 12) ∥ ADRS[16 ∶ 32]
		/// </summary>
		/// <param name="tree"></param>
		public void SetTreeAddress(ulong tree) {
			Utility.toByte(tree, A, TreeOffset + 4);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 24] ∥ toByte(𝑖, 4) ∥ ADRS[28 ∶ 32]
		/// </summary>
		/// <param name="treeHeight"></param>
		public void SetTreeHeight(uint treeHeight) {
			Utility.toByte(treeHeight, A, TreeHeightOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 28] ∥ toByte(𝑖, 4)
		/// </summary>
		/// <param name="treeIndex"></param>
		public void SetTreeIndex(uint treeIndex) {
			Utility.toByte(treeIndex, A, TreeIndexOffset);
		}

		/// <summary>
		/// ADRS ← ADRS[0 ∶ 16] ∥ toByte(𝑌 , 4) ∥ toByte(0, 12)
		/// </summary>
		/// <param name="type"></param>
		public void SetTypeAndClear(AddressType type) {
			A[TypeOffset + 3] = (byte)type;
			Array.Clear(A, 20, 12);
		}
	}
}