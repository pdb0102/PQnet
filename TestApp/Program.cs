using System;
using PQnet;

namespace TestApp {
	class Program {
		static void Main(string[] args) {
			Console.WriteLine("=== LMS Key Generation Debug Test ===\n");

			// Test vector from KAT: SHA256-M32-H5, W1 (simplest parameter set)
			// Source: LMS-keyGen-1.0-SHA256-M32-H5_H10, Test Group 33, Test Case 1
			byte[] seed;
			byte[] i_bytes;
			byte[] expected_pk;
			byte[] actual_pk;
			byte[] actual_sk;
			ILmsHashAlgorithm hash;
			bool success;

			seed = HexToBytes("3B6760DBA1638399CEC56317E449C6DE7D9C2D57B9C02587406D26BF25343489");
			i_bytes = HexToBytes("A497D713D99056A8F05CABC87F0E336D");
			expected_pk = HexToBytes("0000000500000001A497D713D99056A8F05CABC87F0E336D04CB6709BA5E04F3B718CEB6076F9257A0E7641363F50D3A8AF7E9501274EF0D");

			Console.WriteLine("Test Parameters:");
			Console.WriteLine($"  LMS Mode: LMS_SHA256_M32_H5 (typecode: 0x00000005)");
			Console.WriteLine($"  OTS Mode: LMOTS_SHA256_N32_W1 (typecode: 0x00000001)");
			Console.WriteLine($"  Tree Height: 5 (32 leaves)");
			Console.WriteLine($"  Hash: SHA-256 (32 bytes output)");
			Console.WriteLine();

			Console.WriteLine("Input Values:");
			Console.WriteLine($"  Seed (32 bytes): {BytesToHex(seed)}");
			Console.WriteLine($"  I (16 bytes):    {BytesToHex(i_bytes)}");
			Console.WriteLine();

			// Generate the key pair
			Console.WriteLine("Generating key pair...");
			hash = new Sha256LmsHash();
			Lms.GenerateKeyPair(hash, Lms.LMS_SHA256_M32_H5, LmOts.LMOTS_SHA256_N32_W1, i_bytes, seed, out actual_pk, out actual_sk);
			Console.WriteLine("Key pair generated.\n");

			// Compare public keys
			Console.WriteLine("=== Public Key Comparison ===\n");
			Console.WriteLine("Expected PK:");
			PrintHexWithStructure(expected_pk);
			Console.WriteLine();

			Console.WriteLine("Actual PK:");
			PrintHexWithStructure(actual_pk);
			Console.WriteLine();

			// Byte-by-byte comparison
			Console.WriteLine("=== Byte-by-Byte Analysis ===");
			success = CompareBytes(expected_pk, actual_pk);

			if (success) {
				Console.ForegroundColor = ConsoleColor.Green;
				Console.WriteLine("\n✓ PUBLIC KEY MATCHES!");
				Console.ResetColor();
			} else {
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine("\n✗ PUBLIC KEY MISMATCH!");
				Console.ResetColor();
			}

			Console.WriteLine("\nPress any key to exit...");
			Console.ReadKey();
		}

		static void PrintHexWithStructure(byte[] data) {
			string hex;

			hex = BytesToHex(data);

			Console.WriteLine($"  Full hex: {hex}");
			Console.WriteLine($"  Length: {data.Length} bytes");
			Console.WriteLine();
			Console.WriteLine("  Structure breakdown:");

			if (data.Length >= 24) {
				Console.WriteLine($"    [00-03] LMS typecode: {hex.Substring(0, 8)} = 0x{hex.Substring(0, 8)}");
				Console.WriteLine($"    [04-07] OTS typecode: {hex.Substring(8, 8)} = 0x{hex.Substring(8, 8)}");
				Console.WriteLine($"    [08-23] I identifier: {hex.Substring(16, 32)}");

				if (data.Length >= 56) {
					Console.WriteLine($"    [24-55] Root hash:    {hex.Substring(48, 64)}");
				}
			}
		}

		static bool CompareBytes(byte[] expected, byte[] actual) {
			int minLen;
			bool allMatch;
			int firstMismatch;

			minLen = Math.Min(expected.Length, actual.Length);
			allMatch = true;
			firstMismatch = -1;

			if (expected.Length != actual.Length) {
				Console.ForegroundColor = ConsoleColor.Yellow;
				Console.WriteLine($"WARNING: Length mismatch! Expected {expected.Length}, got {actual.Length}");
				Console.ResetColor();
				allMatch = false;
			}

			for (int i = 0; i < minLen; i++) {
				if (expected[i] != actual[i]) {
					if (firstMismatch == -1) {
						firstMismatch = i;
					}
					allMatch = false;
				}
			}

			if (!allMatch && firstMismatch >= 0) {
				Console.ForegroundColor = ConsoleColor.Red;
				Console.WriteLine($"\nFirst mismatch at byte {firstMismatch}:");
				Console.WriteLine($"  Expected: 0x{expected[firstMismatch]:X2}");
				Console.WriteLine($"  Actual:   0x{actual[firstMismatch]:X2}");
				Console.ResetColor();

				// Show context around mismatch
				int start;
				int end;

				start = Math.Max(0, firstMismatch - 4);
				end = Math.Min(minLen, firstMismatch + 5);

				Console.WriteLine($"\nContext (bytes {start}-{end-1}):");
				Console.Write("  Expected: ");
				for (int i = start; i < end; i++) {
					if (i == firstMismatch) {
						Console.ForegroundColor = ConsoleColor.Red;
					}
					Console.Write($"{expected[i]:X2} ");
					Console.ResetColor();
				}
				Console.WriteLine();

				Console.Write("  Actual:   ");
				for (int i = start; i < end; i++) {
					if (i == firstMismatch) {
						Console.ForegroundColor = ConsoleColor.Red;
					}
					Console.Write($"{actual[i]:X2} ");
					Console.ResetColor();
				}
				Console.WriteLine();

				// Identify which field has the mismatch
				if (firstMismatch < 4) {
					Console.WriteLine("\n  Location: LMS typecode field");
				} else if (firstMismatch < 8) {
					Console.WriteLine("\n  Location: OTS typecode field");
				} else if (firstMismatch < 24) {
					Console.WriteLine("\n  Location: I identifier field");
				} else {
					Console.WriteLine("\n  Location: Root hash field");
				}
			}

			return allMatch;
		}

		static byte[] HexToBytes(string hex) {
			int numberChars;
			byte[] bytes;

			numberChars = hex.Length;
			bytes = new byte[numberChars / 2];

			for (int i = 0; i < numberChars; i += 2) {
				bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
			}

			return bytes;
		}

		static string BytesToHex(byte[] bytes) {
			return BitConverter.ToString(bytes).Replace("-", "");
		}
	}
}
