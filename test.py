
import copy
import struct

__all__ = ["AES", "AESModeOfOperationCTR", "AESModeOfOperationCBC", "AESModeOfOperationCFB",
           "AESModeOfOperationECB", "AESModeOfOperationOFB", "AESModesOfOperation", "Counter"]


def _compact_word(word):
    return (word[0] << 24) | (word[1] << 16) | (word[2] << 8) | word[3]

def _string_to_bytes(text):
    return list(ord(c) for c in text)

def _bytes_to_string(binary):
    return "".join(chr(b) for b in binary)

def _concat_list(a, b):
    return a + b


# Python 3 compatibility
try:
    range
except Exception:
    range = range

    # Python 3 supports bytes, which is already an array of integers
    def _string_to_bytes(text):
        if isinstance(text, bytes):
            return text
        return [ord(c) for c in text]

    # In Python 3, we return bytes
    def _bytes_to_string(binary):
        return bytes(binary)

    # Python 3 cannot concatenate a list onto a bytes, so we bytes-ify it first
    def _concat_list(a, b):
        return a + bytes(b)


key= _string_to_bytes("YELLOW SUBMARINE")

        # Convert the key into ints
tk = [ struct.unpack('>i', bytes(key[i:i + 4]))[0] for i in range(0, len(key), 4) ]
print(tk)
