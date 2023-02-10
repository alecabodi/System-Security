#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string.h>
#include <stdlib.h>

#include "sgx_tcrypto.h"
#include "sgx_trts.h"

int enclave_secret = 1337;

typedef struct _sgx_crypto_t {
    sgx_ecc_state_handle_t handle;
    sgx_ec256_private_t sk;
    sgx_ec256_public_t pk;
    sgx_ec256_dh_shared_t shared_key;
} sgx_crypto_t;

sgx_crypto_t sgx_crypto;
uint16_t response;


int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t printSecret()
{
  char buf[BUFSIZ] = {"From Enclave: Hello from the enclave.\n"};
  ocall_print_string(buf);
  printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
  return SGX_SUCCESS;
}



/*************************
 * BEGIN [2. E_A generates key pair]
 *************************/

sgx_status_t generateKeyPair(uint8_t *pk) {

    sgx_status_t sgx_status;

    sgx_status = sgx_ecc256_open_context(&sgx_crypto.handle);
    if (sgx_status != SGX_SUCCESS)
        return sgx_status;

    sgx_status = sgx_ecc256_create_key_pair(&sgx_crypto.sk, &sgx_crypto.pk, sgx_crypto.handle);
    memcpy(pk, &sgx_crypto.pk, 64 * sizeof(uint8_t));

    return sgx_status;
}

/*************************
 * END [2. E_A generates key pair]
 *************************/



/*************************
 * BEGIN [3. E_A computes shared secret]
 *************************/

sgx_status_t computeSharedSecret(uint8_t *tmp_remote_pk) {

    sgx_status_t sgx_status;

    sgx_ec256_public_t remote_pk;
    memcpy(&remote_pk, tmp_remote_pk, 64 * sizeof(uint8_t));

    sgx_status = sgx_ecc256_compute_shared_dhkey(&sgx_crypto.sk, &remote_pk, &sgx_crypto.shared_key, sgx_crypto.handle);

    return sgx_status;
}

/*************************
 * END [3. E_A computes shared secret]
 *************************/



/*************************
 * BEGIN [1. Alice sends PSK to Bob]
 *************************/

sgx_status_t getPSK(uint8_t *encrypted_PSK){

    sgx_status_t sgx_status;

    char *PSK_A = strndup("I AM ALICE", 10);

    uint8_t *PSK = (uint8_t *) malloc(10 * sizeof(uint8_t));

    for (int i = 0; i < 10; i++)
        PSK[i] = PSK_A[i];

    sgx_status = encrypt(PSK, encrypted_PSK, 10);

    return sgx_status;
}

/*************************
 * END [1. Alice sends PSK to Bob]
 *************************/



/*************************
 * BEGIN [1. Alice receives (and checks) PSK from Bob]
 *************************/

sgx_status_t checkPSK(uint8_t *encrypted_PSK){

    sgx_status_t sgx_status;

    uint8_t *decrypted_PSK = (uint8_t *) malloc(10 * sizeof(uint8_t));

    sgx_status = decrypt(encrypted_PSK, decrypted_PSK, 10);
    if (sgx_status != SGX_SUCCESS)
        return sgx_status;

    char *PSK_B = strndup("I AM BOBOB", 10);

    uint8_t *PSK = (uint8_t *) malloc(10 * sizeof(uint8_t));

    for (int i = 0; i < 10; i++)
        PSK[i] = PSK_B[i];

    for (int i = 0; i < 10; i++) {
        if (decrypted_PSK[i] != PSK[i])
            return SGX_ERROR_UNEXPECTED;
    }

    return sgx_status;
}

/*************************
 * END [1. Alice receives (and checks) PSK from Bob]
 *************************/



/*************************
 * BEGIN [4. E_A generates (and encrypts) challenge]
 *************************/

sgx_status_t getChallenge(uint8_t *encrypted_challenge){

    sgx_status_t sgx_status;

    uint8_t a;
    sgx_status = sgx_read_rand((unsigned char *) &a, 1);
    if (sgx_status != SGX_SUCCESS)
        return sgx_status;

    uint8_t b;
    sgx_status = sgx_read_rand((unsigned char *) &b, 1);
    if (sgx_status != SGX_SUCCESS)
        return sgx_status;

    response = a + b; // save response in global variable to check later the response correctness

    uint8_t *challenge = (uint8_t *) malloc(2 * sizeof(uint8_t));
    challenge[0] = a;
    challenge[1] = b;

    sgx_status = encrypt(challenge, encrypted_challenge, 2);

    return sgx_status;
}

/*************************
 * END [4. E_A generates (and encrypts) challenge]
 *************************/



/*************************
 * BEGIN [5. E_A decrypts (and verifies) response]
 *************************/

sgx_status_t checkResponse(uint8_t *encrypted_response, int *correct_result){

    sgx_status_t sgx_status;

    uint8_t *decrypted_response_tmp = (uint8_t *) malloc(2 * sizeof(uint8_t));
    sgx_status = decrypt(encrypted_response, decrypted_response_tmp, 2);

    uint8_t msb = decrypted_response_tmp[0];
    uint8_t lsb = decrypted_response_tmp[1];

    // https://stackoverflow.com/questions/51555676/how-to-divide-an-int-into-two-bytes-in-c
    uint16_t decrypted_response = (uint16_t)((msb << 8) | lsb );

    *correct_result = decrypted_response == response;

    return sgx_status;
}

/*************************
 * END [5. E_A decrypts (and verifies) response]
 *************************/


/* AES encryption and decryption functions */

sgx_status_t encrypt(uint8_t *m, uint8_t *c, size_t len) {

    sgx_status_t sgx_status;

    uint8_t *init_vector = (uint8_t *)calloc(16, sizeof(uint8_t));
    uint32_t ctr_inc_bits = 4; // due to challenge size, 4 counter bits are more than sufficient

    sgx_aes_ctr_128bit_key_t *k_128 = (sgx_aes_ctr_128bit_key_t *) malloc(32 * sizeof(uint8_t));
    memcpy(k_128, sgx_crypto.shared_key.s, 32 * sizeof(uint8_t));

    sgx_status = sgx_aes_ctr_encrypt(k_128, m, (uint32_t) len, init_vector, ctr_inc_bits, c);

    return sgx_status;
}

sgx_status_t decrypt(uint8_t *c, uint8_t *m, size_t len) {

    sgx_status_t sgx_status;

    uint8_t *init_vector = (uint8_t *)calloc(16, sizeof(uint8_t));
    uint32_t ctr_inc_bits = 4; // due to challenge size, 4 counter bits are more than sufficient

    sgx_aes_ctr_128bit_key_t *k_128 = (sgx_aes_ctr_128bit_key_t *) malloc(32 * sizeof(uint8_t));
    memcpy(k_128, sgx_crypto.shared_key.s, 32 * sizeof(uint8_t));

    sgx_status = sgx_aes_ctr_encrypt(k_128, c, (uint32_t) len, init_vector, ctr_inc_bits, m);

    return sgx_status;
}
