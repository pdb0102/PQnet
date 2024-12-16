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
		int upper;
		int lower;
		int index;
		byte[] bytes;

		if (string.IsNullOrEmpty(hex)) {
			return Array.Empty<byte>();
		}

		length = hex.Length;
		if ((length % 2) != 0) {
			throw new InvalidOperationException();
		}

		index = 0;
		bytes = new byte[length / 2];
		for (int l = 0; l < length; l += 2) {
			upper = hex[l];

			if (('0' <= upper) && (upper <= '9')) {
				upper -= 48;
			} else if (('A' <= upper) && (upper <= 'F')) {
				upper -= 55;
			} else if (('a' <= upper) && (upper <= 'f')) {
				upper -= 87;
			} else {
				throw new InvalidDataException(string.Format(System.Globalization.CultureInfo.InvariantCulture, "The character at index {0} of \'{1}\' is not a hexadecimal digit.", l, hex[l]));
			}

			upper <<= 4;

			lower = hex[l + 1];

			if (('0' <= lower) && (lower <= '9')) {
				lower -= 48;
			} else if (('A' <= lower) && (lower <= 'F')) {
				lower -= 55;
			} else if (('a' <= lower) && (lower <= 'f')) {
				lower -= 87;
			} else {
				throw new InvalidDataException(string.Format(System.Globalization.CultureInfo.InvariantCulture, "The character at index {0} of \'{1}\' is not a hexadecimal digit.", l, hex[l + 1]));
			}

			bytes[index++] = (byte)(upper + lower);
		}

		return bytes;
	}
}
