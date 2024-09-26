#include <limits.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>

#include <openssl/sha.h>
#include <secp256k1.h>
#include "ripemd160.h"

#ifdef COUNT_KEYS
#include <stdatomic.h>
#include <unistd.h>

static atomic_uint_least64_t count;
#endif

#define SECRET_KEY_SIZE 32
#define PUBLIC_KEY_SIZE 33
#define NUM_THREADS 12

static pthread_mutex_t mutex0 = PTHREAD_MUTEX_INITIALIZER;

typedef int i32;
typedef uint8_t u8;
typedef uint64_t u64;
typedef uint32_t u32;
typedef struct pt_arg
{
    u64 n;
    i32 result;
} pt_arg;

union secret_key
{
    u8 bytes[32];
    u64 nums[4];
};

static int cmp_target(u8 data[]);
static void printHex(u8 *data, u64 len);
static void init_secret_keys(union secret_key keys[], u64 n);
static void *make_keys(void *_args);
#ifdef COUNT_KEYS
static void *counter(void *_args);
#endif

int main(void)
{
    pthread_t threads[NUM_THREADS];
    pt_arg argvals[NUM_THREADS];
    void *rets[NUM_THREADS];
    u64 start = 1;
    for (i32 i = 0; i < NUM_THREADS; i++)
    {
        // start at a random offset
        u64 r;
        if (getrandom((void *)(&r), sizeof(r), 0) < sizeof(r)) {
            printf("Data for thread %d was not randomized.\n", i);
        }

        argvals[i].n = start + r;
        start += (UINT64_MAX / 12);

        if (pthread_create(&threads[i], NULL, &make_keys, &argvals[i]))
        {
            printf("Unable to start thread %d.\n", i);
        }
    }

#ifdef COUNT_KEYS
    pthread_t counter_thread;
    pthread_create(&counter_thread, NULL, &counter, NULL);
#endif

    // Wait for all pthreads to finish. This should only complete if
    // all pthreads return early due to an error. Otherwise, the pthread
    // that discovers the correct secret key will print the output to
    // stdout and then terminate execution of the process.
    for (i32 i = 0; i < NUM_THREADS; i++)
    {
        pthread_join(threads[i], &rets[i]);
    }
    for (i32 i = 0; i < NUM_THREADS; i++)
    {
        printf("Thread %d returned: %d.\n", i, *(i32 *)(rets[i]));
    }

    return 1;
}

int cmp_target(u8 data[])
{
    // 1BY8GQbnueYofwSuFAT3USAhGjPrkxDdW9 converted from base58, minus the first byte and last four bytes.
    const u8 target[] = {0x73, 0x94, 0x37, 0xbb, 0x3d, 0xd6, 0xd1, 0x98, 0x3e, 0x66, 0x62, 0x9c, 0x5f, 0x08, 0xc7, 0x0e, 0x52, 0x76, 0x93, 0x71};

    for (i32 i = 0; i < 20; i++)
    {
        if (target[i] != data[i])
            return 0;
    }
    return 1;
}

void printHex(u8 *data, u64 len)
{
    for (u64 i = 0; i < len; i++)
    {
        printf("%02x", data[i]);
    }
    printf("\n");
    return;
}

void init_secret_keys(union secret_key keys[], u64 n)
{
    keys[0].nums[3] = n;
    keys[1].nums[3] = n;
    keys[2].nums[3] = n;
    keys[3].nums[3] = n;

    keys[0].bytes[SECRET_KEY_SIZE - 9] = (1 << 2);
    keys[1].bytes[SECRET_KEY_SIZE - 9] = (1 << 2) | (1);
    keys[2].bytes[SECRET_KEY_SIZE - 9] = (1 << 2) | (1 << 1);
    keys[3].bytes[SECRET_KEY_SIZE - 9] = (1 << 2) | (1 << 1) | (1);
}

void *make_keys(void *_args)
{
    pt_arg *args = (pt_arg *)_args;
    args->result = 0;

    // DECLARE/INITIALIZE secp256k1 CONTEXT
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    // SET INITIAL SECRET KEY VALUES
    union secret_key secret_keys[4] = {};
    init_secret_keys(secret_keys, args->n);

    // SECP256K1 PUBLIC KEYS
    secp256k1_pubkey raw_public_keys[4];
    u8 public_keys[4][PUBLIC_KEY_SIZE];

    u8 sha_hashes[4][SHA256_DIGEST_LENGTH];
    u8 rmd_hashes[4][RIPEMD160_DIGEST_LENGTH];
    i32 offset;
    while (1)
    {
        for (i32 i = 0; i < 4; i++)
        {
            u64 n = PUBLIC_KEY_SIZE;
            if (!secp256k1_ec_pubkey_create(ctx, &raw_public_keys[i], secret_keys[i].bytes))
            {
                goto error;
            }

            secp256k1_ec_pubkey_serialize(ctx, public_keys[i], &n, &raw_public_keys[i], SECP256K1_EC_COMPRESSED);
            SHA256(public_keys[i], n, sha_hashes[i]);

            ripemd160(sha_hashes[i], SHA256_DIGEST_LENGTH, rmd_hashes[i]);


            if (cmp_target(rmd_hashes[i]))
            {
                offset = i;
                goto success;
            }

#ifdef COUNT_KEYS
            count++;
#endif

#ifdef DEBUG
            pthread_mutex_lock(&mutex0);
            printf("CHECKED KEY\n");
            printf("%s", "secret key:     ");
            printHex(secret_keys[i].bytes, SECRET_KEY_SIZE);
            printf("%s", "public key:     ");
            printHex(public_keys[i], PUBLIC_KEY_SIZE);
            printf("%s", "SHA256 hash:    ");
            printHex(sha_hashes[i], SHA256_DIGEST_LENGTH);
            printf("%s", "RIPEMD160 hash: ");
            printHex(rmd_hashes[i], RIPEMD160_DIGEST_LENGTH);
            pthread_mutex_unlock(&mutex0);
#endif
        secret_keys[i].nums[3]++;
        }
    }

error:
    args->result = 1;
    secp256k1_context_destroy(ctx);
    pthread_exit(&(args->result));

success:
    pthread_mutex_lock(&mutex0);
    printf("SOLUTION FOUND\n");
    printf("%s", "secret key:     ");
    printHex(secret_keys[offset].bytes, SECRET_KEY_SIZE);
    printf("%s", "public key:     ");
    printHex(public_keys[offset], PUBLIC_KEY_SIZE);
    printf("%s", "SHA256 hash:    ");
    printHex(sha_hashes[offset], SHA256_DIGEST_LENGTH);
    printf("%s", "RIPEMD160 hash: ");
    printHex(rmd_hashes[offset], RIPEMD160_DIGEST_LENGTH);
    pthread_mutex_unlock(&mutex0);
    // at this point, it's ok to kill the entire program
    exit(0);
};

#ifdef COUNT_KEYS
void *counter(void *_args)
{
    // Convert milliseconds to microseconds
    u64 last = 0;
    while(1)
    {
        usleep(1 * 1000 * 1000);
        u64 cur = count;
        cur *= 4;
        printf("%"PRIu64" keys checked in the last second\n", cur - last);
        last = cur;
    }
}
#endif