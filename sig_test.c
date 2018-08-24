/* identity-based signature test program
 * Ben Lynn
 */
/*
Copyright (C) 2001 Benjamin Lynn (blynn@cs.stanford.edu)

See LICENSE for license
*/
#include <stdlib.h>
#include <string.h>
#include "ibe_progs.h"
#include "ibe.h"
#include "format.h"
#include "crypto.h"
#include "benchmark.h"	//for bm_report_*

int main(int argc, char **argv)
{
    params_t params;
    byte_string_t priv, pub;

    byte_string_t priv2, pub2;
    byte_string_t sig;
    byte_string_t message;
    byte_string_t master;
    byte_string_t cert, cshare[2];
    byte_string_t mshare[2];
    char *id = "test";
    int status;
    int i;
    unsigned int result;

    IBE_init();

	/*IBE_setup(params, master, 2048, 224, "test");*/
	IBE_setup(params, master, 3072, 256, "test");
    /*IBE_setup(params, master, 1024, 384, "test");*/

    IBE_keygen(priv, pub, params);

    IBE_keygen(priv2, pub2, params);

    byte_string_set(message, "12345678901234567890123456789012");

    //Rather than work out the certifcate directly from the master key,
    //I'll demonstrate how secret sharing works.
    //This is done so that an attacker must compromise all the servers in
    //order to break the system.

    //During setup the master key is split into two pieces
    //One server guards mshare[0], and the other guards mshare[1]
    IBE_split_master(mshare, master, 2, 2, params);

    //The user then requests a certificate share from each server
    IBE_certify_share(cshare[0], mshare[0], pub, id, params);
    IBE_certify_share(cshare[1], mshare[1], pub, id, params);

    //...and combines them to get a full certificate on their public key
    IBE_combine(cert, cshare, params);



    /*printf("message: ");*/
    /*byte_string_fprintf(stdout, message, " %02X");*/
    /*printf("\n");*/

    /*printf("priv: ");*/
    /*byte_string_fprintf(stdout, priv, " %02X");*/
    /*printf("\n");*/

    /*printf("cert: ");*/
    /*byte_string_fprintf(stdout, cert, " %02X");*/
    /*printf("\n");*/

    /*printf("params: ");*/
    /*printf("\n");*/

	int count = 200;
	result = 1;
	double totalSign = 0;
	double totalVerify = 0;
	for(int i=0; i<count; ++i) {
		bm_put(bm_get_time(), "t0");
		IBE_sign(sig, message, priv, cert, params);
		bm_put(bm_get_time(), "t1");
		result &= IBE_verify(sig, message, pub, id, params);
		bm_put(bm_get_time(), "t2");
		totalSign += (bm_get("t1") - bm_get("t0"));
		totalVerify += (bm_get("t2") - bm_get("t1"));
	}
    fprintf(stdout, "sign time: %lf\n", 1000.0 * totalSign / count);
    fprintf(stdout, "verify time: %lf\n", 1000.0 * totalVerify / count);


	/*clock_t t1, t2;*/
	/*t1 = clock();*/ /*for(int i=0; i<count; ++i) {*/
		/*IBE_sign(sig, message, priv, cert, params);*/
	/*}*/
	/*t2 = clock();*/
	/*printf("sign: %f seconds\n", 1.0 * (t2-t1) / 1000000.0 / count);*/


    /*printf("sig: ");*/
    /*byte_string_fprintf(stdout, sig, " %02X");*/
    /*printf("\n");*/

    /*printf("pub: ");*/
    /*byte_string_fprintf(stdout, pub, " %02X");*/
    /*printf("\n");*/

    /*printf("id: ");*/
    /*printf(" %s", id);*/
    /*printf("\n");*/

	/*t1 = clock();*/
	/*for(int i=0; i<count; ++i) {*/
		/*result &= IBE_verify(sig, message, pub, id, params);*/
	/*}*/
	/*t2 = clock();*/
	/*printf("verify: %f seconds\n", 1.0 * (t2-t1) / 1000000.0 / count);*/

	/*if (!result) {*/
		/*printf("signature verifies\n");*/
	/*} else {*/
		/*printf("bug: signature does not verify\n");*/
	/*}*/

    if (IBE_verify(sig, message, pub2, id, params)) {
		printf("bug: signature verifies with wrong public key\n");
    }

    params_clear(params);

    byte_string_clear(pub2); byte_string_clear(priv2);
    byte_string_clear(pub); byte_string_clear(priv);
    byte_string_clear(cert);
    byte_string_clear(cshare[0]);
    byte_string_clear(cshare[1]);
    byte_string_clear(master);
    byte_string_clear(mshare[0]);
    byte_string_clear(mshare[1]);
    byte_string_clear(message);
    byte_string_clear(sig);

    IBE_clear();

    return 0;
}
