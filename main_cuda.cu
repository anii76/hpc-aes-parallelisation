#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <inttypes.h>

#define WS 8             // word size
#define CN 62            // characters number
#define DICT_SIZE 285465 // dictionary size
#define THREADS_NUM 512  // number of threads for each block

#include "../utils/aes.h"
#include "../utils/aes.c"

#ifdef __CUDA_ARCH__
#define CONSTANT __constant__
#else
#define CONSTANT
#endif

__constant__ unsigned char c_target[32]; // constant memory copy of encrypted password

CONSTANT uint8_t key[] = "aaaaaaaaaaaaaaaa";
CONSTANT uint8_t iv[] = "bbbbbbbbbbbbbbbb";
CONSTANT uint8_t str[] = "00000000"; //password
CONSTANT struct AES_ctx ctx;

//Custom implematation of memcmp for cuda
__device__ __host__ int cuda_memcmp(void *s1, void *s2, int n)
{
    unsigned char *p = (unsigned char *)s1;
    unsigned char *q = (unsigned char *)s2;
    if (s1 == s2)
    {
        return 0;
    }
    for (int i = 0; i < n; i++)
    {
        if (p[i] != q[i])
        {
            return -1;
        }
    }
    return 0;
}

__host__ __device__ void encrypt(uint8_t *plain)
{
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_encrypt_buffer(&ctx, plain, 32);
}

__host__ __device__ void decrypt(uint8_t *cipher)
{
    AES_init_ctx_iv(&ctx, key, iv);
    AES_CBC_decrypt_buffer(&ctx, cipher, 32);
}

__host__ __device__ void uint64_to_uint8(uint8_t mesg[], uint64_t num)
{
    for (int i = 0; i < 8; i++)
        mesg[i] = num >> (8 - 1 - i) * 8;
}

// dictionary kernel
__global__ void dict_kernel(unsigned char *dictionary, unsigned char *result)
{
    int index = blockIdx.x * blockDim.x + threadIdx.x;
    if (index < DICT_SIZE)
    {
        unsigned char *word = (unsigned char *)dictionary[index * 8];
        /*Extend to 32 while content is 8*/
        uint8_t buf[32];
        for (int i = 0; i < 32; i++)
        {
            if (i < 8)
            {
                buf[i] = (uint8_t)word[i];
            }
            else
            {
                buf[i] = 0x00;
            }
        }
        uint8_t *buf_p = (uint8_t *)buf;
        encrypt(buf_p);

        // the thread found the solution
        if (cuda_memcmp(buf_p, c_target, 32) == 0)
        {
            result = (unsigned char *)word;
            return;
        }
    }
}

__global__ void brute_kernel(uint8_t *result, int offset, int *success)
{
    uint64_t word = blockIdx.x * blockDim.x + threadIdx.x + offset;

    if (word < 0xFFFFFFFFFFFFFFFF)
    {
        word += 3472328296227680304; // index translation: thread 0 tries "00000000" and so on

        //convert uint64_t word to uint8_t array
        uint8_t *uword = (uint8_t *)malloc(8 * sizeof(uint8_t));
        uint64_to_uint8(uword, word);

        /*Extend to 32 while content is 8*/
        uint8_t buf[32];
        for (int i = 0; i < 32; i++)
        {
            if (i < 8)
            {
                buf[i] = (uint8_t)uword[i];
            }
            else
            {
                buf[i] = 0x00;
            }
        }
        uint8_t *buf_p = (uint8_t *)buf; //

        encrypt(buf_p);
        // to avoid Memory err
        free(uword);
        if (cuda_memcmp(buf_p, c_target, 32) == 0)
        {                                  // the thread found the solution
            result = (unsigned char *)str; //uword;
            *success = 1;
            return;
        }
    }
}

int main(int argc, char **argv)
{

    unsigned char *upassword;
    uint8_t *crypted_target;
    char *curr_word = (char *)malloc(WS * sizeof(char));
    unsigned char *u_curr_word;
    FILE *dictionary;
    // device & host dictionary
    unsigned char h_dictionary[DICT_SIZE][WS];
    unsigned char *d_dictionary;

    // decryption result
    unsigned char *result = NULL;
    unsigned char *d_result = NULL;
    int *success;
    int _success = 0;

    cudaError_t err;

    // password to find
    char password[] = "00000000";

    // verify if the user inserted eight characters password
    if ((int)strlen(password) != 8)
    {
        printf("%d\n", (int)strlen(password));
        perror("error: insert an eight characters password");
    }
    printf("target:%s\n", password);

    // conversion and encryption
    upassword = (unsigned char *)(password);
    printf("encoded target:");
    for (int i = 0; i < 8; i++)
    {
        printf("%02x", upassword[i]);
    }
    /*Extend to 32 while content is 8*/
    /*We will use this inside encrypt/decrypt only*/
    uint8_t buf[32];
    for (int i = 0; i < 32; i++)
    {
        if (i < 8)
        {
            buf[i] = (uint8_t)upassword[i];
        }
        else
        {
            buf[i] = 0x00;
        }
    }
    uint8_t *buf_p = (uint8_t *)buf;
    printf("\nencoded buf:");
    for (int i = 0; i < 32; ++i)
    {
        printf("%.2x", buf_p[i]);
    }
    encrypt(buf_p);

    crypted_target = (uint8_t *)buf_p;

    printf("\nencrypted target:");
    for (int i = 0; i < 32; i++)
    {
        printf("%02x", crypted_target[i]);
    }

    // start counting clock cycles
    clock_t start_t = clock();

    puts("\nPhase 1: Try with dictionary");
    puts("opening dictionary...");
    if ((dictionary = fopen("./dictionary.txt", "r")) == NULL)
    {
        perror("error: dictionary not found");
    }
    puts("dictionary opened...");
    puts("");

    // dictionary import and converting
    puts("dictionary import and converting...");
    int i = 0;
    while (!feof(dictionary))
    {
        fscanf(dictionary, "%8s", curr_word);
        u_curr_word = (unsigned char *)curr_word;
        for (int j = 0; j < WS; j++)
        {
            h_dictionary[i][j] = u_curr_word[j];
        }
        i++;
    }

    //closing the file
    fclose(dictionary);
    puts("import/conversion done...");
    puts("");

    // dictionary attack
    // gpu malloc and memset
    puts("\ngpu malloc and memset...");
    cudaMalloc((void **)&success, sizeof(int));
    cudaMemset(success, 0, sizeof(int));
    err = cudaMalloc((void **)&d_result, WS * sizeof(unsigned char));
    if (err != cudaSuccess)
    {
        printf("\n %s\n", cudaGetErrorString(err));
    }
    cudaMemcpyToSymbol(c_target, crypted_target, 32 * sizeof(unsigned char));

    err = cudaMalloc((void **)&d_dictionary, DICT_SIZE * WS * sizeof(unsigned char));
    if (err != cudaSuccess)
    {
        printf("\n %s\n", cudaGetErrorString(err));
    }
    puts("malloc and memset done...");
    puts("");

    //gpu memcpy
    puts("gpu memcpy...");
    cudaMemcpy(d_dictionary, h_dictionary, DICT_SIZE * WS * sizeof(unsigned char), cudaMemcpyHostToDevice);
    cudaMemcpyToSymbol(c_target, crypted_target, 32 * sizeof(unsigned char));

    puts("gpu memcpy done...");
    puts("");

    // dictionary kernel launch
    puts("dictionary kernel launch...");
    int block_size = DICT_SIZE / THREADS_NUM + 1;
    dict_kernel<<<block_size, THREADS_NUM>>>(d_dictionary, d_result);

    // copying result
    cudaMemcpy(result, d_result, WS * sizeof(unsigned char), cudaMemcpyDeviceToHost);

    //check if password was found
    if (result != NULL)
    {
        printf("\npassword found:");
        for (int i = 0; i < 8; i++)
        {
            printf("%02x ", result[i]);
        }

        // gpu memory deallocation
        cudaFree(d_dictionary);

        // stop counting clock cycles and calculate elapsed time
        clock_t end_t = clock();
        clock_t total_t = (end_t - start_t);
        printf("\nElapsed Time:%.3f seconds\n", (double)total_t / ((double)CLOCKS_PER_SEC));

        return 0;
    }
    else
    {
        puts("password not in dictionary...");
    }

    // gpu memory deallocation
    cudaFree(d_dictionary);

    // Phase 2
    puts("\nPhase2: brute force. This may take a long time...");
    unsigned long long brute_size = 0xFFFFFFFFFFFFFFFF;
    unsigned int brute_blocks = 512, brute_threads = 512;

    // a kernel launch processes (brute_blocks * brute_threads) elements
    //compare the crypted_target with possible hashes (2^64 − 1 which equals 18,446,744,073,709,551,615)
    //(ps le temps CUDA peut être amélioré en parallelisant la boucle exterieure)
    //dim3 block(brute_blocks, brute_threads)
    //dim3 grid
    for (int i = 0; i < (brute_size / (brute_blocks * brute_threads)) + 1; i++)
    {
        brute_kernel<<<brute_blocks, brute_threads>>>(d_result, i * (brute_blocks * brute_threads), success);
        err = cudaGetLastError();
        if (err != cudaSuccess)
        {
            printf("CUDA Error: %s\n", cudaGetErrorString(err));
            break;
        }
        cudaMemcpy(&_success, success, sizeof(int), cudaMemcpyDeviceToHost);

        /*// copying result
		    err = cudaMemcpy(result, d_result, WS*sizeof(unsigned char), cudaMemcpyDeviceToHost);
        if ( err != cudaSuccess ){
          printf("CUDA Error: %s\n", cudaGetErrorString(err));       
        } */

        //check if password was found
        if (_success == 1)
        {
            printf("\nsucess %d\n", _success);
            printf("\npassword found:");
            for (int i = 0; i < 8; i++)
            {
                printf("%02x ", upassword[i]);
            }
            break;
        }
    }

    // stop counting clock cycles and calculate elapsed time
    clock_t end_t = clock();
    clock_t total_t = (end_t - start_t);
    printf("\nElapsed Time:%f seconds\n", (double)total_t / ((double)CLOCKS_PER_SEC));

    cudaFree(d_result);
    cudaFree(success);

    return 0;
}