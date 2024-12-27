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
/// <summary>
/// 
/// </summary>
// FIPS 205 Section 4.2
public enum AddressType : byte {
	WotsHash = 0,
	WotsPk = 1,
	Tree = 2,
	ForsTree = 3,
	ForsRoots = 4,
	WotsPrf = 5,
	ForsPrf = 6
}

/// <summary>
/// ADRS - (Section 4.2)
/// </summary>
public interface IAddress {
	public IAddress Clone();
	public void SetLayerAddress(uint layer);
	public void SetTreeAddress(ulong tree);
	public void SetTypeAndClear(AddressType type);
	public void SetKeyPairAddress(uint keyPair);
	public void CopyKeyPairAddress(IAddress other);
	public void SetChainAddress(uint chain);
	public void SetTreeHeight(uint treeHeight);
	public void SetHashAddress(uint hash);
	public void SetTreeIndex(uint treeIndex);
	public uint TreeIndex { get; }
	public uint KeyPairAddress { get; }
	public byte[] Bytes { get; }
}


public class Sha2Address : IAddress {
	private const int LayerOffset = 0;
	private const int TreeOffset = 1;
	private const int TypeOffset = 9;
	private const int KeyPairAddrOffset = 10;
	private const int ChainAddrOffset = 17;
	private const int HashAddrOffset = 21;
	private const int TreeHeightOffset = 17;
	private const int TreeIndexOffset = 18;
	public byte[] A;

	/// <summary>
	/// 
	/// </summary>
	public Sha2Address() {
		A = new byte[32];
	}

	public byte[] Bytes {
		get {
			return A;
		}
	}

	public uint TreeIndex {
		get {
			return Utility.toInt(A, TreeOffset);
		}
	}

	public uint KeyPairAddress {
		get {
			return Utility.toInt(A, KeyPairAddrOffset);
		}
	}

	public IAddress Clone() {
		Sha2Address clone;

		clone = new Sha2Address();
		Array.Copy(A, clone.A, A.Length);
		return clone;
	}

	/// <summary>
	/// Copy the layer, tree and keypair fields 
	/// </summary>
	/// <param name="other"></param>
	public void CopyKeyPairAddress(IAddress other) {
		Array.Copy(((Sha2Address)other).A, 0, A, 0, TreeOffset + 8);
		Array.Copy(((Sha2Address)other).A, KeyPairAddrOffset, A, KeyPairAddrOffset, 4);
	}

	public void SetChainAddress(uint chain) {
		A[ChainAddrOffset] = (byte)chain;
	}

	public void SetHashAddress(uint hash) {
		A[HashAddrOffset] = (byte)hash;
	}

	public void SetKeyPairAddress(uint keyPair) {
		Utility.toByte(keyPair, A, KeyPairAddrOffset);
	}

	public void SetLayerAddress(uint layer) {
		Utility.toByte(layer, A, LayerOffset);
	}

	public void SetTreeAddress(ulong tree) {
		Utility.toByte(tree, A, TreeOffset);
	}

	public void SetTreeHeight(uint treeHeight) {
		Utility.toByte(treeHeight, A, TreeHeightOffset);
	}

	public void SetTreeIndex(uint treeIndex) {
		Utility.toByte(treeIndex, A, TreeIndexOffset);
	}

	public void SetTypeAndClear(AddressType type) {
		A[TypeOffset] = (byte)type;
		Array.Clear(A, 10, 12);
	}
}

public class ShakeAddress : IAddress {
	private const int LayerOffset = 0;
	private const int TreeOffset = 4;
	private const int TypeOffset = 16;
	private const int KeyPairAddrOffset = 20;
	private const int ChainAddrOffset = 24;
	private const int HashAddrOffset = 28;
	private const int TreeHeightOffset = 24;
	private const int TreeIndexOffset = 28;
	public byte[] A;

	/// <summary>
	/// 
	/// </summary>
	public ShakeAddress() {
		A = new byte[32];
	}

	public byte[] Bytes {
		get {
			return A;
		}
	}

	public uint TreeIndex {
		get {
			return Utility.toInt(A, TreeIndexOffset);
		}
	}

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
	/// Copy the layer, tree and keypair fields 
	/// </summary>
	/// <param name="other"></param>
	public void CopyKeyPairAddress(IAddress other) {
		Array.Copy(((Sha2Address)other).A, 0, A, 0, TreeOffset + 8);
		Array.Copy(((Sha2Address)other).A, KeyPairAddrOffset, A, KeyPairAddrOffset, 4);
	}

	public void SetChainAddress(uint chain) {
		Utility.toByte(chain, A, ChainAddrOffset);
	}

	public void SetHashAddress(uint hash) {
		Utility.toByte(hash, A, HashAddrOffset);
	}

	public void SetKeyPairAddress(uint keyPair) {
		Utility.toByte(keyPair, A, KeyPairAddrOffset);
	}

	public void SetLayerAddress(uint layer) {
		Utility.toByte(layer, A, LayerOffset);
	}

	public void SetTreeAddress(ulong tree) {
		Utility.toByte(tree, A, TreeOffset + 4);
	}

	public void SetTreeHeight(uint treeHeight) {
		Utility.toByte(treeHeight, A, TreeHeightOffset);
	}

	public void SetTreeIndex(uint treeIndex) {
		Utility.toByte(treeIndex, A, TreeIndexOffset);
	}

	public void SetTypeAndClear(AddressType type) {
		A[TypeOffset + 3] = (byte)type;
		Array.Clear(A, 20, 12);
	}
}
