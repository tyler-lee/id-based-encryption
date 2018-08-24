/* Simple IBE test program
 * Ben Lynn
 */
/*
Copyright (C) 2001 Benjamin Lynn (blynn@cs.stanford.edu)

See LICENSE for license
*/
#include "ibe.h"
#include "benchmark.h"	//for bm_report_*

int main(void)
{
    char *id;
    params_t params;
    byte_string_t U;
    byte_string_t secret;
    byte_string_t key;
    byte_string_t master;

    //initialize IBE library
    IBE_init();

    //generate new system parameters:
    //128-bit prime, 64-bit subgroup size

    /*IBE_setup(params, master, 512, 160, "test");*/
	/*IBE_setup(params, master, 1024, 224, "test");*/
	/*IBE_setup(params, master, 1536, 256, "test");*/
	IBE_setup(params, master, 3840, 384, "test");

    id = "blynn@stanford.edu";

    printf("IBE test program\n");
    printf("Test ID: %s\n", id);

    //generate a random secret and its encryption
    printf("generating key...\n");

	int count = 100;
	double totalEnc = 0;
	double totalDec = 0;
	for(int i=0; i<count; ++i) {
		bm_put(bm_get_time(), "lhr-enc0");
		IBE_KEM_encrypt(secret, U, id, params);
		bm_put(bm_get_time(), "lhr-enc1");

		//print ciphertext in hexadecimal
		/*printf("U =");*/
		/*byte_string_printf(U, " %02X");*/
		/*printf("\n");*/

		/*printf("secret =");*/
		/*byte_string_printf(secret, " %02X");*/
		/*printf("\n");*/
		byte_string_clear(secret);

		//Extract the private key corresponding to my ID
		//This is not the normal way of getting a private key;
		//normally the master secret is unknown on the decryption side
		//and they have obtained their private key by fetching it from the PKG

		/*printf("extracting...\n");*/
		IBE_extract(key, master, id, params);
		//The key is now stored in keytext and has length keytextlen

		//Recover the secret from its encryption
		/*printf("recovering secret...\n");*/
		bm_put(bm_get_time(), "lhr-dec0");
		IBE_KEM_decrypt(secret, U, key, params);
		bm_put(bm_get_time(), "lhr-dec1");

		//Print it out. Hopefully it'll be the same as before
		/*printf("secret =");*/
		/*byte_string_printf(secret, " %02X");*/
		/*printf("\n");*/

		totalEnc += (bm_get("lhr-enc1") - bm_get("lhr-enc0"));
		totalDec += (bm_get("lhr-dec1") - bm_get("lhr-dec0"));
	}
    fprintf(stdout, "enc time: %lf\n", 1000.0 * totalEnc / count);
    fprintf(stdout, "dec time: %lf\n", 1000.0 * totalDec / count);

    //free memory used by IBE library
    params_clear(params);
    IBE_clear();
    byte_string_clear(U);
    byte_string_clear(key);
    byte_string_clear(secret);
    byte_string_clear(master);

    return 0;
}
