from math import log2

from libhannah.xor import xor


def entropy(buffer: bytes) -> float:  # Possibly broken, 3.5 -> 5 is english, 7.5 - 8 is encrypted
    wherechar = []
    histlen = 0
    hist = []
    for i in range(len(buffer)):
        hist.append(0)
    for i in range(256):
        wherechar.append(-1)

    for byte in buffer:
        if wherechar[byte] == -1:
            wherechar[byte] = histlen
            histlen += 1
        hist[wherechar[byte]] += 1

    H = 0
    for i in range(histlen):
        H -= hist[i] / histlen * log2(hist[i] / histlen)

    return H


character_frequencies = [
    .08167,  # 'a'
    .01492,  # 'b'
    .02782,  # 'c'
    .04253,  # 'd'
    .12702,  # 'e'
    .02228,  # 'f'
    .02015,  # 'g'
    .06094,  # 'h'
    .06094,  # 'i'
    .00153,  # 'j'
    .00772,  # 'k'
    .04025,  # 'l'
    .02406,  # 'm'
    .06749,  # 'n'
    .07507,  # 'o'
    .01929,  # 'p'
    .00095,  # 'q'
    .05987,  # 'r'
    .06327,  # 's'
    .09056,  # 't'
    .02758,  # 'u'
    .00978,  # 'v'
    .02360,  # 'w'
    .00150,  # 'x'
    .01974,  # 'y'
    .00074,  # 'z'
    .13000  # ' '
]


def is_english(buffer: bytes) -> float:
    num_characters = []
    for i in range(256):
        num_characters.append(0)

    for byte in buffer:
        num_characters[byte] += 1

    for i in range(256):
        num_characters[i] /= len(buffer)

    score = 0
    for i in range(26):
        score += abs(character_frequencies[i] - num_characters[i + ord('a')])

    score += abs(character_frequencies[26] - num_characters[ord(' ')])

    # Scores less than 0.75 are pretty good.
    return score


def hamming_distance(buffer1, buffer2):
    assert (len(buffer1) == len(buffer2));

    xored = xor(buffer1, buffer2)
    distance = 0
    for byte in xored:
        distance += byte >> 0 & 0x1
        distance += byte >> 1 & 0x1
        distance += byte >> 2 & 0x1
        distance += byte >> 3 & 0x1
        distance += byte >> 4 & 0x1
        distance += byte >> 5 & 0x1
        distance += byte >> 6 & 0x1
        distance += byte >> 7 & 0x1

    return distance
