namespace mldsa_net.test.AVCP;
internal class Utilities {
	public static byte[] HexToBytes(string hex, out string error) {
		int length;
		int upper;
		int lower;
		int index;
		byte[] bytes;

		if ((hex == null) || (hex.Length == 0)) {
			error = null;
			return Array.Empty<byte>();
		}

		length = hex.Length;
		if ((length % 2) != 0) {
			error = "Invalid hex string; not multiple of 2";
			return null;
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
				error = $"Invalid character '{upper}' at position {l}";
				return null;
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
				error = $"Invalid character '{lower}' at position {l + 1}";
				return null;
			}

			bytes[index++] = (byte)(upper + lower);
		}

		error = null;
		return bytes;
	}

}
