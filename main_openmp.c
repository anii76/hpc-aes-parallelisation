#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/conf.h>
#include <time.h>
#include <inttypes.h>
#include <omp.h>
#include "aes.c"

#define WS 8             // word size
#define CN 62            // characters number
#define DICT_SIZE 285465 // dictionary size
#define THREAD_NUM 8

int main(int argc, char **argv)
{

    unsigned char *key = (unsigned char *)"0123456789abcdef";

    char *password = (char *)malloc(WS * sizeof(char)); 
    unsigned char *upassword;                           // unsigned char version of the password
    unsigned char crypted_target[64];                   // unsigned char version of the encrypted password

    char *curr_word = (char *)malloc(WS * sizeof(char)); // readed from dictionary or generated
    unsigned char *u_curr_word;                          // uint8_t version of curr_word

    FILE *dictionary;                          // dictionary
    unsigned char h_dictionary[DICT_SIZE][WS]; 

    char characters[CN] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
                           'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
                           'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z'};

    // decryption result
    unsigned char *result = NULL; 

    // password to find 
    password = "31122099";
    // verify if the user inserted eight characters password
    if ((int)strlen(password) != 8)
    {
        printf("%d\n", (int)strlen(password));
        perror("error: insert an eight characters password");
    }
    printf("target:%s\n", password);

    // conversion and encryption
    upassword = (unsigned char *)(password);
    int crypted_len = encrypt(upassword, WS, key, crypted_target);
    printf("crypted target:");
    for (int i = 0; i < crypted_len; i++)
    {
        printf("%02x ", crypted_target[i]);
    }

    //OpenMP specific thread num
    omp_set_num_threads(THREAD_NUM);

    // start counting clock cycles
    clock_t start_t = clock();

    puts("\nPhase 1: Try with dictionary");
    // open dictionary file
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
        // import
        fscanf(dictionary, "%8s", curr_word);
        // conversion
        u_curr_word = (unsigned char *)curr_word;
        // insert into the array
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

    int id;
    unsigned char hash_word[64];
    unsigned char *word;
// dictionary attack
#pragma omp parallel
    {
#pragma omp for private(hash_word, word)
        for (int i = 0; i < DICT_SIZE; i++)
        {
            word = (unsigned char *)h_dictionary[i];
            int hash_word_len = encrypt(word, WS, key, hash_word);
            if (memcmp(hash_word, crypted_target, hash_word_len) == 0)
            {
                result = (unsigned char *)word;
                printf("index : %d\n", i);
                for (int i = 0; i < hash_word_len; i++)
                {
                    printf("%02x ", hash_word[i]);
                }
                id = omp_get_thread_num();
                printf("\nThread : (%d)\n", id);
                        // stop counting clock cycles and calculate elapsed time
        clock_t end_t = clock();
        clock_t total_t = (end_t - start_t);
        printf("\nElapsed Time:%.3f seconds\n", (double)total_t / ((double)CLOCKS_PER_SEC));

        exit(0);
            }
        }
    }
    //check if password was found
    if (result != NULL)
    {
        printf("\npassword found:");
        for (int i = 0; i < 8; i++)
        {
            printf("%02x ", result[i]);
        }
    }
    else
    {
        puts("password not in dictionary...");
    }

    // Phase 2
    puts("\nPhase2: brute force. This may take a long time...");

    //brute force attack
    
    unsigned char passw[8];
    unsigned char passw_hash[64];

//OpenMP collapse nested loops into a parallel runtime.
#pragma omp parallel
    {
#pragma omp for collapse(8)
        for (int i = 0; i < CN; i++)
        {
            for (int j = 0; j < CN; j++)
            {
                for (int k = 0; k < CN; k++)
                {
                    for (int l = 0; l < CN; l++)
                    {
                        for (int m = 0; m < CN; m++)
                        {
                            for (int n = 0; n < CN; n++)
                            {
                                for (int o = 0; o < CN; o++)
                                {
                                    for (int p = 0; p < CN; p++)
                                    {
                                        //if (success) goto end;
                                        //generate password attempt based on the position of the for loops
                                        passw[0] = (unsigned char)characters[i];
                                        passw[1] = (unsigned char)characters[j];
                                        passw[2] = (unsigned char)characters[k];
                                        passw[3] = (unsigned char)characters[l];
                                        passw[4] = (unsigned char)characters[m];
                                        passw[5] = (unsigned char)characters[n];
                                        passw[6] = (unsigned char)characters[o];
                                        passw[7] = (unsigned char)characters[p];

                                        unsigned char *p = (unsigned char *)passw;
                                        int pass_len = encrypt(p, WS, key, passw_hash);

                                        if (memcmp(passw_hash, crypted_target, pass_len) == 0)
                                        {
                                            result = (unsigned char *)passw;
                                            for (int i = 0; i < pass_len; i++)
                                            {
                                                printf("%02x ", passw_hash[i]);
                                            }
                                            printf("\n");

                                            printf("\npassword found:");
                                            for (int i = 0; i < 8; i++)
                                            {
                                                printf("%02x ", result[i]);
                                            }

                                            // stop counting clock cycles and calculate elapsed time
                                            clock_t end_t = clock();
                                            clock_t total_t = (end_t - start_t);
                                            printf("\nElapsed Time:%f seconds\n", (double)total_t / ((double)CLOCKS_PER_SEC));

                                            id = omp_get_thread_num();
                                            printf("Thread : (%d)\n", id);
#pragma omp cancel for
                                            exit(0);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    //check if password was found
    if (result != NULL)
    {
        printf("\npassword found:");
        for (int i = 0; i < 8; i++)
        {
            printf("%02x ", result[i]);
        }

        // stop counting clock cycles and calculate elapsed time
        clock_t end_t = clock();
        clock_t total_t = (end_t - start_t);
        printf("\nElapsed Time:%f seconds\n", (double)total_t / ((double)CLOCKS_PER_SEC));
    }

    return 0;
}