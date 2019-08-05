import base64
with open('raw.txt') as input_file:
    ciphertext = base64.standard_b64decode(input_file.read())

    
import math
def str_to_int_array(s):
    return [ord(c) for c in s]
#chars to ascii vals

def xor_lists(a, b):
    return map(lambda x: x[0] ^ x[1], zip(a, b))

def hex_to_int_array(h):
    cparts = []
    c1_left = h
    while c1_left > 0:
        c1_left, r = divmod(c1_left, 256)
        cparts.append(int(r))
    cparts.reverse()
    return cparts
    #print(list(xor_lists(hex_to_int_array(0x09e1c5f70a65ac519458e7e53f36),hex_to_int_array(0x6c73d5240a948c86981bc294814d))))
#hex value to 256 ceiling int array

def int_array_to_hex_string(c):
    return ''.join(map(lambda x: hex(x)[2:].zfill(2), c))
    
def int_array_to_hex(c):
    return ''.join(map(lambda x: hex(x)[2:].zfill(2), c))


# c1_hex = 0x09e1c5f70a65ac519458e7e53f36

def is_letter(n):
    return (n >= ord('a') and n <= ord('z')) or (n >= ord('A') and n <= ord('Z'))

def int_array_to_human_string(a):
    def get_letter(n):
        if is_letter(n): return chr(n)
        return '.'
    return map(get_letter, a)
"""Prints out a string where the value at the index is a letter if possible, otherwise prints ."""
# int_array_to_human_string(list(c2)
    
def hamdist(hex1, hex2):
    diffInt= hex1 ^ hex2
    length= 2
    count= 0
    for x in range(int(math.pow(2,length*4)), -1, -1):
        tempDiff= diffInt- math.pow(2,x)
        if (tempDiff >= 0):
            count= count +1
            diffInt= tempDiff
    return count

def hamdist2(intArr1, intArr2):
    count= 0
    for x in range(0, len(intArr1)):
        diffInt= intArr1[x] ^ intArr2[x]
        for x in range(4, -1, -1):
            tempDiff= diffInt- math.pow(2,x)
            if (tempDiff >= 0):
                count= count +1
                diffInt= tempDiff
    return count
#bitwise distance between two hexes

def bitsToHamming(bitWord1, bitWord2):
    bytes_1 = [byte for byte in bitWord1]
    bytes_2 = [byte for byte in bitWord2]
    xor_bytes = [b1 ^ b2 for b1,b2 in zip(bytes_1, bytes_2)]
    hamming_distance = 0
    for byte in xor_bytes:
        hamming_distance += sum([1 for bit in bin(byte) if bit == '1'])
        
    return hamming_distance
#print(bitsToHamming(b"this is a test", b"wokka wokka!!!"))



"""
    Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.

    For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes,
    and find the edit distance between them. Normalize this result by dividing by KEYSIZE.


distances= []
for keysize in range(2,41):
    hammingSum=0
    hammingAveForKeysize= 0
    filesize= len(ciphertext)
    for x in range(0, int(filesize/ keysize)-1): #filesize or sampleSize
        hammingSum += hamdist2(ciphertext[x*keysize: (x+1)*keysize], ciphertext[(x+1)*keysize: (x+2)*keysize])
    distances.append(hammingSum/filesize) #keysize in num and denom
#print(distances)
print(min(distances))
print(distances[27])
print(distances.index(min(distances)))      
min block size is therefore 29 w hamm dis 3.4

    The KEYSIZE with the smallest normalized edit distance is probably the key.
    You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of
    2 and average the distances.
29
    Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
"""
def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i:i+n]
#print(list(chunks(ciphertext, 29)))
chunkedFile= chunks(ciphertext, 29)
print(list(chunkedFile))
"""
    Now transpose the blocks: make a block that is the first byte of every block,
    and a block that is the second byte of every block, and so on.
    
    Solve each block as if it was single-character XOR.
    You already have code to do this.
    
    For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key
    XOR key byte for that block. Put them together and you have the key.
"""


######English Score Solution#####
def get_english_score(input_bytes):
    """Compares each input byte to a character frequency 
    chart and returns the score of a message based on the
    relative frequency the characters occur in the English
    language.
    """

    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])
#for byte in ciphertext[0:10]:
#    print(chr(byte))
testBlock= b''

for x in chunks(ciphertext, 29):
    testBlock += bytes(x[2])

print(list(chunkedFile))   
#for byte in testBlock:
    #print(chr(byte))

print(get_english_score(testBlock))

def single_char_xor(input_bytes, char_value):
    """Returns the result of each byte being XOR'd with a single value.
    """
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value])
    return output_bytes


def bruteforce_single_char_xor(ciphertext):
    """Performs a singlechar xor for each possible value(0,255), and
    assigns a score based on character frequency. Returns the result
    with the highest score.
    """
    potential_messages = []
    for key_value in range(256):
        message = single_char_xor(ciphertext, key_value)
        score = get_english_score(message)
        data = {
            'message': message,
            'score': score,
            'key': key_value
            }
        potential_messages.append(data)
    return sorted(potential_messages, key=lambda x: x['score'], reverse=True)[0]


def break_repeating_key_xor(ciphertext):
    """Attempts to break repeating-key XOR encryption.
    """
    average_distances = []

    # Take the keysize from suggested range 
    for keysize in range(2,41):

        # Initialize list to store Hamming distances for this keysize 
        distances = []

        # Break the ciphertext into chunks the length of the keysize
        chunks = [ciphertext[i:i+keysize] for i in range(0, len(ciphertext), keysize)]
        
        while True:
            try:
                # Take the two chunks at the beginning of the list and 
                # get the Hamming distance 
                chunk_1 = chunks[0]
                chunk_2 = chunks[1]
                distance = calculate_hamming_distance(chunk_1, chunk_2)

                # Normalize this result by dividing by KEYSIZE
                distances.append(distance/keysize)

                # Remove these chunks so when the loop starts over, the
                # Hamming distance for the next two chunks can be calculated
                del chunks[0]
                del chunks[1]

            # When an exception occurs (indicating all chunks have 
            # been processed) break out of the loop.
            except Exception as e:
                break
        result = {
            'key': keysize,
            'avg distance': sum(distances) / len(distances)
            }
        average_distances.append(result)
    possible_key_lengths = sorted(average_distances, key=lambda x: x['avg distance'])[0]
    possible_plaintext = []

    # Will populate with a single character as each transposed 
    # block has been single-byte XOR brute forced
    key = b''
    possible_key_length = possible_key_lengths['key']
    for i in range(possible_key_length):
        
        # Creates an block made up of each nth byte, where n
        # is the keysize
        block = b''
        for j in range(i, len(ciphertext), possible_key_length):
            block += bytes([ciphertext[j]])
        key += bytes([bruteforce_single_char_xor(block)['key']]) 
    possible_plaintext.append((repeating_key_xor(ciphertext, key), key)) 
    return max(possible_plaintext, key=lambda x: get_english_score(x[0]))


def repeating_key_xor(message_bytes, key):
    """Returns message XOR'd with a key. If the message, is longer
    than the key, the key will repeat.
    """
    output_bytes = b''
    index = 0
    for byte in message_bytes:
        output_bytes += bytes([byte ^ key[index]])
        if (index + 1) == len(key):
            index = 0
        else:
            index += 1
    return output_bytes
"""
def main():
    with open('raw.txt') as input_file:
        ciphertext = base64.b64decode(input_file.read())
    result, key = break_repeating_key_xor(ciphertext)
    print("Key: {}\nMessage: {}".format(key, result))
"""
