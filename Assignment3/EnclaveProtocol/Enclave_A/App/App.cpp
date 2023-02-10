#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

#include <arpa/inet.h>
#include <sys/socket.h>

// port 8080 is assumed to be available (change port if this is not the case)
#define PORT 8080

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
        {
                SGX_ERROR_UNEXPECTED,
                "Unexpected error occurred.",
                NULL
        },
        {
                SGX_ERROR_INVALID_PARAMETER,
                "Invalid parameter.",
                NULL
        },
        {
                SGX_ERROR_OUT_OF_MEMORY,
                "Out of memory.",
                NULL
        },
        {
                SGX_ERROR_ENCLAVE_LOST,
                "Power transition occurred.",
                "Please refer to the sample \"PowerTransition\" for details."
        },
        {
                SGX_ERROR_INVALID_ENCLAVE,
                "Invalid enclave image.",
                NULL
        },
        {
                SGX_ERROR_INVALID_ENCLAVE_ID,
                "Invalid enclave identification.",
                NULL
        },
        {
                SGX_ERROR_INVALID_SIGNATURE,
                "Invalid enclave signature.",
                NULL
        },
        {
                SGX_ERROR_OUT_OF_EPC,
                "Out of EPC memory.",
                NULL
        },
        {
                SGX_ERROR_NO_DEVICE,
                "Invalid SGX device.",
                "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
        },
        {
                SGX_ERROR_MEMORY_MAP_CONFLICT,
                "Memory map conflicted.",
                NULL
        },
        {
                SGX_ERROR_INVALID_METADATA,
                "Invalid enclave metadata.",
                NULL
        },
        {
                SGX_ERROR_DEVICE_BUSY,
                "SGX device was busy.",
                NULL
        },
        {
                SGX_ERROR_INVALID_VERSION,
                "Enclave version was invalid.",
                NULL
        },
        {
                SGX_ERROR_INVALID_ATTRIBUTE,
                "Enclave was not authorized.",
                NULL
        },
        {
                SGX_ERROR_ENCLAVE_FILE_ACCESS,
                "Can't open enclave file.",
                NULL
        },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
        printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}


/* Application entry */
int SGX_CDECL main(int argc, char *argv[]) {

    (void)(argc);
    (void)(argv);
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enclave initialization failed.\n");
        return -1;
    }
    printf("From App: Enclave creation success. \n");


    /* SOCKET INIT (from https://www.geeksforgeeks.org/socket-programming-cc/) */

    int Bob_socket;
    int Alice_socket;

    struct sockaddr_in addrB;
    size_t addrB_len = sizeof(addrB);

    if ((Bob_socket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        printf("\n Socket creation error\n");
        return -1;
    }

    addrB.sin_family = AF_INET;
    addrB.sin_port = htons(PORT);

    if (inet_pton(AF_INET, "127.0.0.1", &addrB.sin_addr) <= 0) {
        printf("\nInvalid address\n");
        return -1;
    }

    if ((Alice_socket = connect(Bob_socket, (struct sockaddr*)&addrB, addrB_len)) < 0) {
        printf("\nConnection Failed\n");
        return -1;
    }


    /* START PROTOCOL */

    printf("From App: Write your protocol here ... \n");

    sgx_status_t sgx_status;



    /* AUTHENTICATION */

    /*************************
     * BEGIN [2. E_A generates key pair]
     *************************/

    uint8_t *pkA = (uint8_t *) malloc(64 * sizeof(uint8_t));

    generateKeyPair(global_eid, &sgx_status, pkA);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /*************************
     * END [2. E_A generates key pair]
     *************************/



    /*************************
     * BEGIN [1. Alice sends public key to Bob]
     *************************/

    send(Bob_socket, pkA, 64 * sizeof(uint8_t), 0);

    /*************************
     * END [1. Alice sends public key to Bob]
     *************************/



    /*************************
     * BEGIN [1. Alice receives public key from Bob]
     *************************/

    uint8_t *pkB = (uint8_t *) malloc(64 * sizeof(uint8_t));
    read(Bob_socket, pkB, 64 * sizeof(uint8_t));

    /*************************
     * END [1. Alice receives public key from Bob]
     *************************/



    /*************************
     * BEGIN [3. E_A computes shared secret]
     *************************/

    computeSharedSecret(global_eid, &sgx_status, pkB);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /*************************
     * END [3. E_A computes shared secret]
     *************************/



    /*************************
     * BEGIN [1. Alice sends PSK to Bob]
     *************************/

    uint8_t *encrypted_PSK_A = (uint8_t *) malloc(10 * sizeof(uint8_t));

    getPSK(global_eid, &sgx_status, encrypted_PSK_A);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    send(Bob_socket, encrypted_PSK_A, 10 * sizeof(uint8_t), 0);

    /*************************
     * END [1. Alice sends PSK to Bob]
     *************************/



    /*************************
     * BEGIN [1. Alice receives (and checks) PSK from Bob]
     *************************/

    uint8_t *encrypted_PSK_B = (uint8_t *) malloc(10 * sizeof(uint8_t));
    read(Bob_socket, encrypted_PSK_B, 10 * sizeof(uint8_t));

    checkPSK(global_eid, &sgx_status, encrypted_PSK_B);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /*************************
     * END [1. Alice receives (and checks) PSK from Bob]
     *************************/



    /* CHALLENGE */

    for (int i = 0; i < 20; i++) {

        /*************************
         * BEGIN [4. E_A generates (and encrypts) challenge]
         *************************/

        uint8_t *encrypted_challenge = (uint8_t *) malloc(2 * sizeof(uint8_t));

        getChallenge(global_eid, &sgx_status, encrypted_challenge);
        if (sgx_status != SGX_SUCCESS) {
            print_error_message(sgx_status);
            return -1;
        }

        /*************************
         * END [4. E_A generates (and encrypts) challenge]
         *************************/



        /*************************
         * BEGIN [1. Alice sends challenge to Bob]
         *************************/

        send(Bob_socket, encrypted_challenge, 2 * sizeof(uint8_t), 0);

        /*************************
         * END [1. Alice sends challenge to Bob]
         *************************/



        /*************************
         * BEGIN [1. Alice receives response from Bob]
         *************************/

        uint8_t *encrypted_response = (uint8_t *) malloc(2 * sizeof(uint8_t));
        read(Bob_socket, encrypted_response, 2 * sizeof(uint8_t));

        /*************************
         * END [1. Alice receives response from Bob]
         *************************/



        /*************************
         * BEGIN [5. E_A decrypts (and verifies) response]
         *************************/

        int correct_result = 0;
        checkResponse(global_eid, &sgx_status, encrypted_response, &correct_result);
        if (sgx_status != SGX_SUCCESS) {
            print_error_message(sgx_status);
            return -1;
        }

        if (!correct_result)
            return -1;

        /*************************
         * END [5. E_A decrypts (and verifies) response]
         ************************/

    }

/* commented out not to show enclave internals */

//     printSecret(global_eid, &sgx_status);
//     if (sgx_status != SGX_SUCCESS) {
//         print_error_message(sgx_status);
//         return -1;
//     }s


    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);
    printf("From App: Enclave destroyed.\n");

    /* Tear down socket */
    close(Alice_socket);

    return 0;
}

