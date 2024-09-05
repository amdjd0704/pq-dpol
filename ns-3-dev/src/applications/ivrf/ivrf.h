
#ifndef IVRF_H
#define IVRF_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/sha.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <time.h>
#include <oqs/oqs.h>

#include "drbg_rng.h"

#define LOGN 2
#define LAMBDA 16
#define SEED_LENGTH 48

#define HASH_LENGTH (2 * LAMBDA)
#define MU_LENGTH (2 * LAMBDA)

#define BENCHMARK_ITERATION 1

typedef struct 
{
    unsigned char hash[HASH_LENGTH];
} TREE_NODE;

void keygen(std::vector<TREE_NODE> &tree, AES256_CTR_DRBG_struct *s, AES256_CTR_DRBG_struct *s_prime);
void keyupd(AES256_CTR_DRBG_struct *s, AES256_CTR_DRBG_struct *s_prime);

void eval(unsigned char *v, unsigned char *y, std::vector<TREE_NODE> &ap, unsigned char *pk, unsigned char *sig, size_t &sig_len, const unsigned char *mu1, const unsigned char *mu2, const uint32_t i_in, const uint32_t j_in, const AES256_CTR_DRBG_struct *s, const AES256_CTR_DRBG_struct *s_prime, const std::vector<TREE_NODE> &tree);

uint32_t verify(const unsigned char *mu1, const unsigned char *mu2, const uint32_t i_in, const uint32_t j_in, const unsigned char *v, const unsigned char *y, const std::vector<TREE_NODE> &ap, const unsigned char *pk, const unsigned char *sig, const size_t sig_len, const TREE_NODE *root);

int test();
#endif /* IVRF_H */
