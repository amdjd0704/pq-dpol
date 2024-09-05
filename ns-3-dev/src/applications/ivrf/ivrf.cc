#include "ivrf.h" 


#define N (1 << LOGN)
#define T 100


#define SEED_LENGTH 48
#define EXPANDED_SEED_LENGTH 128

unsigned char expanded_seed[EXPANDED_SEED_LENGTH];
size_t expanded_seed_offset = 0;

void custom_randombytes(uint8_t *random_array, size_t bytes_to_read) {
    if (expanded_seed_offset + bytes_to_read > EXPANDED_SEED_LENGTH) {
        expanded_seed_offset = 0; // 재설정
    }
    memcpy(random_array, expanded_seed + expanded_seed_offset, bytes_to_read);
    expanded_seed_offset += bytes_to_read;
}

void expand_seed(const unsigned char *seed, unsigned char *expanded_seed, size_t expanded_seed_length) {
    EVP_MD_CTX *mdctx;
    if ((mdctx = EVP_MD_CTX_new()) == NULL) {
        printf("EVP_MD_CTX_new failed\n");
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_DigestInit_ex(mdctx, EVP_shake256(), NULL)) {
        printf("EVP_DigestInit_ex failed\n");
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_DigestUpdate(mdctx, seed, SEED_LENGTH)) {
        printf("EVP_DigestUpdate failed\n");
        exit(EXIT_FAILURE);
    }

    if (1 != EVP_DigestFinalXOF(mdctx, expanded_seed, expanded_seed_length)) {
        printf("EVP_DigestFinalXOF failed\n");
        exit(EXIT_FAILURE);
    }

    EVP_MD_CTX_free(mdctx);
}

void generate_keypair(const unsigned char *seed, unsigned char *public_key, unsigned char *secret_key) {
    expand_seed(seed, expanded_seed, EXPANDED_SEED_LENGTH);
    expanded_seed_offset = 0; 

    OQS_randombytes_custom_algorithm(custom_randombytes);

    OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig == NULL) {
        fprintf(stderr, "OQS_SIG_new failed\n");
        exit(EXIT_FAILURE);
    }

    OQS_STATUS status = OQS_SIG_keypair(sig, public_key, secret_key);
    if (status != OQS_SUCCESS) {
        fprintf(stderr, "OQS_SIG_keypair failed\n");
        OQS_SIG_free(sig);
        exit(EXIT_FAILURE);
    }

    OQS_SIG_free(sig);
}



void keygen(std::vector<TREE_NODE> &tree, AES256_CTR_DRBG_struct *s, AES256_CTR_DRBG_struct *s_prime) {
    unsigned char buf[15879];
    uint32_t i, j;
    unsigned char pk_i[OQS_SIG_falcon_512_length_public_key], sk_i[OQS_SIG_falcon_512_length_secret_key];

    unsigned char seed_s[SEED_LENGTH]={0,}, seed_s_prime[SEED_LENGTH]={0,};
    AES256_CTR_DRBG_struct s_i, s_prime_i;
    unsigned char r_i[SEED_LENGTH]={0,};
    
    
    OQS_randombytes(seed_s, SEED_LENGTH);
    OQS_randombytes(seed_s_prime, SEED_LENGTH);
    
    
    drbg_randombytes_init(&s_i, seed_s, NULL, LAMBDA);
    memcpy(s, &s_i, sizeof(s_i));
    drbg_randombytes_init(&s_prime_i, seed_s_prime, NULL, LAMBDA);
    memcpy(s_prime, &s_prime_i, sizeof(s_prime_i));
    

    

    for (i = 0; i < N; i++) {
    
        // Derive x_{i,0} by generating random bytes
        //OQS_randombytes(tree[N + i].hash, HASH_LENGTH);
	drbg_randombytes(&s_i, tree[N + i].hash, HASH_LENGTH);
	
        // x_{i,j+1} = H(x_{i,j})
        for (j = 0; j < T - 1; j++) {
            memcpy(buf, tree[N + i].hash, HASH_LENGTH);
            SHA256(buf, HASH_LENGTH, tree[N + i].hash);
        }

	/* Derive r_i by running G.Next on s' */
	drbg_randombytes(&s_prime_i, r_i, SEED_LENGTH);
	

        // (pk_i, sk_i) <-- FALCON.KeyGen()
        OQS_SIG *sig = OQS_SIG_new(OQS_SIG_alg_falcon_512);
        if (sig == nullptr) {
            std::cerr << "Could not create signature object" << std::endl;
            exit(EXIT_FAILURE);
        }
        //OQS_SIG_keypair(sig, pk_i, sk_i);
        generate_keypair(r_i, pk_i, sk_i);

        // x_{i,t}=H(x_{i,t-1},pk_i)
        memcpy(buf, tree[N + i].hash, HASH_LENGTH);
        memcpy(buf + HASH_LENGTH, pk_i, OQS_SIG_falcon_512_length_public_key);
        SHA256(buf, HASH_LENGTH + OQS_SIG_falcon_512_length_public_key, tree[N + i].hash);

        OQS_SIG_free(sig);
        
        
    }

    // Merkle tree
    for (i = N; i >= 2; i >>= 1) {
        for (j = i >> 1; j < i; j++) {
            memcpy(buf, tree[2 * j].hash, HASH_LENGTH);
            memcpy(buf + HASH_LENGTH, tree[2 * j + 1].hash, HASH_LENGTH);
            SHA256(buf, 2 * HASH_LENGTH, tree[j].hash);
        }
    }

    
    
   
}

void keyupd(AES256_CTR_DRBG_struct *s, AES256_CTR_DRBG_struct *s_prime)
{
	unsigned char buf[SEED_LENGTH];
	
	/* (s, s') <-- (G.Next(s), G.Next(s')) */
	drbg_randombytes(s, buf, HASH_LENGTH);
	drbg_randombytes(s_prime, buf, SEED_LENGTH);
}

void eval(unsigned char *v, unsigned char *y, std::vector<TREE_NODE> &ap, unsigned char *pk, unsigned char *sig, size_t &sig_len, const unsigned char *mu1, const unsigned char *mu2, const uint32_t i_in, const uint32_t j_in, const AES256_CTR_DRBG_struct *s, const AES256_CTR_DRBG_struct *s_prime, const std::vector<TREE_NODE> &tree) {
    unsigned char buf[39943];
    uint32_t i, j;

    unsigned char sk[OQS_SIG_falcon_512_length_secret_key];
    unsigned char r[SEED_LENGTH];
    AES256_CTR_DRBG_struct s_in, s_prime_in;
    
    /* Parse sk_av=(s_i, x_{i,0}, s_i', r_i) */
    memcpy(&s_in, s, sizeof(s_in));
    drbg_randombytes(&s_in, y, HASH_LENGTH);
    memcpy(&s_prime_in, s_prime, sizeof(s_prime_in));
    drbg_randombytes(&s_prime_in, r, SEED_LENGTH);
	
    /* y = H^{t-1-j}(x_{i,0}) */
    for (j = 0; j < T - 1 - j_in; j++)
    {
        memcpy(buf, y, HASH_LENGTH);
        SHA256(buf, HASH_LENGTH, y);
    }
	


	
    

    // v = H(y,\mu1)
    memcpy(buf, y, HASH_LENGTH);
    memcpy(buf + HASH_LENGTH, mu1, MU_LENGTH);
    SHA256(buf, HASH_LENGTH + MU_LENGTH, v);

    // pk <-- Falcon.KeyGen()
    generate_keypair(r, pk, sk);
    
    
    // sig <-- Falcon.Sign(sk, \mu_2)
    OQS_SIG *sig_obj = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    if (sig_obj == nullptr) {
        std::cerr << "Could not create signature object" << std::endl;
        exit(EXIT_FAILURE);
    }
    sig_len = OQS_SIG_falcon_512_length_signature;
    OQS_SIG_sign(sig_obj, sig, &sig_len, mu2, MU_LENGTH, sk);

    // Copy the hash values of siblings along the path to the root for i-th leaf (index is N+i)
    j = 0;
    for (i = N + i_in; i > 1; i >>= 1) {
        memcpy(ap[j].hash, tree[i ^ 1].hash, HASH_LENGTH);

        j++;
    }

    OQS_SIG_free(sig_obj);
}

uint32_t verify(const unsigned char *mu1, const unsigned char *mu2, const uint32_t i_in, const uint32_t j_in, const unsigned char *v, const unsigned char *y, const std::vector<TREE_NODE> &ap, const unsigned char *pk, const unsigned char *sig, const size_t sig_len, const TREE_NODE *root) {
    unsigned char buf[4097];
    uint32_t i, j, i_cur;
    unsigned char v_new[HASH_LENGTH];
    unsigned char root_new[HASH_LENGTH];
    int falcon_verify_res;



    // H(y,\mu1)
    memcpy(buf, y, HASH_LENGTH);
    memcpy(buf + HASH_LENGTH, mu1, MU_LENGTH);
    SHA256(buf, HASH_LENGTH + MU_LENGTH, v_new);

    // if v != H(y,\mu1), return 0
    if (memcmp(v_new, v, HASH_LENGTH) != 0) {
        return 0;
    }

    // Falcon.Verify(pk, sig, \mu2)
    OQS_SIG *sig_obj = OQS_SIG_new(OQS_SIG_alg_falcon_512);
    falcon_verify_res = OQS_SIG_verify(sig_obj, mu2, MU_LENGTH, sig, sig_len, pk);

    if (falcon_verify_res != OQS_SUCCESS) {
        return 0;
    }

    // y'=H^{j}(y)
    memcpy(root_new, y, HASH_LENGTH);
    for (j = 0; j < j_in; j++) {
        memcpy(buf, root_new, HASH_LENGTH);
        SHA256(buf, HASH_LENGTH, root_new);
    }

    // x_i=H(y',pk)
    memcpy(buf, root_new, HASH_LENGTH);
    memcpy(buf + HASH_LENGTH, pk, OQS_SIG_falcon_512_length_public_key);
    SHA256(buf, HASH_LENGTH + OQS_SIG_falcon_512_length_public_key, root_new);
   
	
    // Compute root' by using x_{i}, index i_in, and AP
    i_cur = i_in;
    for (i = 0; i < LOGN; i++) {
        if (i_cur & 1) {
            memcpy(buf, ap[i].hash, HASH_LENGTH);
            memcpy(buf + HASH_LENGTH, root_new, HASH_LENGTH);
        } else {
            memcpy(buf, root_new, HASH_LENGTH);
            memcpy(buf + HASH_LENGTH, ap[i].hash, HASH_LENGTH);
        }
        SHA256(buf, 2 * HASH_LENGTH, root_new);
        i_cur >>= 1;
    }


    // if root' != pk_av, return 0
    if (memcmp(root_new, root->hash, HASH_LENGTH) != 0) {
        printf("\n root' != pk_av\n");
        return 0;
    }

    OQS_SIG_free(sig_obj);
    return 1;
}

int test() {
    std::vector<TREE_NODE> tree(2 * N);
    AES256_CTR_DRBG_struct s_orig, s_prime_orig, s, s_prime;
    uint32_t i;
    uint32_t i_in, j_in;
    unsigned char v[HASH_LENGTH], y[HASH_LENGTH];
    std::vector<TREE_NODE> ap(LOGN);
    unsigned char mu1[MU_LENGTH]={0,}, mu2[MU_LENGTH]={0,};
    
    unsigned char pk[OQS_SIG_falcon_512_length_public_key], sig[OQS_SIG_falcon_512_length_signature];
    size_t sig_len;
    

    
    uint32_t verify_res;
    
    uint32_t benchmark_iteration; 
    
    memset(tree.data(), 0, tree.size() * sizeof(TREE_NODE));
    

    keygen(tree, &s_orig, &s_prime_orig);

    

srand(time(nullptr));

// j = 0
for (benchmark_iteration = 0; benchmark_iteration < BENCHMARK_ITERATION; benchmark_iteration++) {
    //OQS_randombytes(mu1, MU_LENGTH);
    //OQS_randombytes(mu2, MU_LENGTH);
    memcpy(&s, &s_orig, sizeof(s));
    memcpy(&s_prime, &s_prime_orig, sizeof(s_prime));
    i_in = rand() % N;
    j_in = 0;
    
    for (i = 0; i < i_in; i++)
		{
			keyupd(&s, &s_prime);
		}
    

    eval(v, y, ap, pk, sig, sig_len, mu1, mu2, i_in, j_in, &s, &s_prime, tree);

    verify_res = verify(mu1, mu2, i_in, j_in, v, y, ap, pk, sig, sig_len, tree.data() + 1);
    printf("\n%d\n",verify_res);

    

}

// j = t - 1
for (benchmark_iteration = 0; benchmark_iteration < BENCHMARK_ITERATION; benchmark_iteration++) {
    //OQS_randombytes(mu1, MU_LENGTH);
    //OQS_randombytes(mu2, MU_LENGTH);
    memcpy(&s, &s_orig, sizeof(s));
    memcpy(&s_prime, &s_prime_orig, sizeof(s_prime));
    i_in = rand() % N;
    j_in = T - 1;
    
    for (i = 0; i < i_in; i++)
		{
			keyupd(&s, &s_prime);
		}
    

    eval(v, y, ap, pk, sig, sig_len, mu1, mu2, i_in, j_in, &s, &s_prime, tree);

    verify_res = verify(mu1, mu2, i_in, j_in, v, y, ap, pk, sig, sig_len, tree.data() + 1);
    printf("\n%d\n",verify_res);
    
    
}


return 0;
}
