namespace TestApp;
internal static class Extensions {
	private static readonly char[] HexDigits = new char[] { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F' };

	public static string ToHexString(this ArraySegment<byte> bytes) {
		int b;
		int index;
		char[] characters;

		if (bytes.Count < 1) {
			return string.Empty;
		}

		index = 0;
		characters = new char[bytes.Count * 2];
		for (int l = bytes.Offset, end = bytes.Offset + bytes.Count; l < end; l++) {
			b = bytes.Array[l];

			characters[index++] = HexDigits[b >> 4];
			characters[index++] = HexDigits[b & 0x0F];
		}

		return new string(characters);
	}

	public static byte[] HexToBytes(this string hex) {
		int length;
		byte[] bytes;
		int index;

		if (string.IsNullOrEmpty(hex)) {
			return Array.Empty<byte>();
		}

		length = hex.Length;
		if ((length % 2) != 0) {
			throw new InvalidOperationException("Hex string must have an even length.");
		}

		bytes = new byte[length / 2];
		index = 0;

		for (int i = 0; i < length; i += 2) {
			int upper = GetHexValue(hex[i]);
			int lower = GetHexValue(hex[i + 1]);

			bytes[index++] = (byte)((upper << 4) + lower);
		}

		return bytes;
	}

	private static int GetHexValue(char hex) {
		return hex switch {
			>= '0' and <= '9' => hex - '0',
			>= 'A' and <= 'F' => hex - 'A' + 10,
			>= 'a' and <= 'f' => hex - 'a' + 10,
			_ => throw new InvalidDataException($"The character '{hex}' is not a valid hexadecimal digit.")
		};
	}
}
