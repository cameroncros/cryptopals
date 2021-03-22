#include <stdlib.h>
#include <math.h>

double character_frequencies[] = {
        .08167,  // 'a'
        .01492,  // 'b'
        .02782,  // 'c'
        .04253,  // 'd'
        .12702,  // 'e'
        .02228,  // 'f'
        .02015,  // 'g'
        .06094,  // 'h'
        .06094,  // 'i'
        .00153,  // 'j'
        .00772,  // 'k'
        .04025,  // 'l'
        .02406,  // 'm'
        .06749,  // 'n'
        .07507,  // 'o'
        .01929,  // 'p'
        .00095,  // 'q'
        .05987,  // 'r'
        .06327,  // 's'
        .09056,  // 't'
        .02758,  // 'u'
        .00978,  // 'v'
        .02360,  // 'w'
        .00150,  // 'x'
        .01974,  // 'y'
        .00074,  // 'z'
        .13000   // ' '
};

double is_english(unsigned char *str, size_t length) {
    double num_characters[256] = {0};
    for (int i = 0; i < length; i++) {
        num_characters[str[i]]++;
    }
    for (int i = 0; i < 256; i++) {
        num_characters[i] /= length;
    }
    double score = 0;
    for (int i = 0; i < 26; i++) {
        score += fabs(character_frequencies[i] - num_characters[i + 'a']);
    }
    score += fabs(character_frequencies[26] - num_characters[' ']);

    // Scores less than 0.75 are pretty good.
    return score;
}

double entropy(unsigned char *str, size_t str_len) {
    int wherechar[256] = {0};
    int histlen = 0;
    int *hist = calloc(str_len, sizeof(int));

    for (int i = 0; i < 256; i++) wherechar[i] = -1;
    for (size_t i = 0; i < str_len; i++) {
        if (wherechar[(int) str[i]] == -1) {
            wherechar[(int) str[i]] = histlen;
            histlen++;
        }
        hist[wherechar[(int) str[i]]]++;
    }

    double H;
    H = 0;
    for (int i = 0; i < histlen; i++) {
        H -= (double) hist[i] / histlen * log2((double) hist[i] / histlen);
    }
    free(hist), hist = NULL;
    return H;
}