/* Benchmarking helper routines
 * Ben Lynn
 */

/*
Copyright (C) 2001 Benjamin Lynn (blynn@cs.stanford.edu)

See LICENSE for license
*/

#include <stdio.h>
#include <string.h>
#include "get_time.h"
#include "benchmark.h"

struct benchmark_s {
    double time;
    char name[100];
};

static struct benchmark_s bmtable[1000];

static int bmcount = 0;

void bm_put(double t, char *s)
{
    int i;
    for (i=0; i<bmcount; i++) {
	if (!strcmp(bmtable[i].name, s)) break;
    }
    if (i == bmcount) {
	bmcount++;
	strcpy(bmtable[i].name, s);
    }

    bmtable[i].time = t;
}

double bm_get(char *s)
{
    int i;
    for (i=0; i<bmcount; i++) {
	if (!strcmp(bmtable[i].name, s)) return bmtable[i].time;
    }
    return 0.0;
}

double bm_get_time(void)
{
    return get_time();
}

void bm_report_encrypt()
{
    fprintf(stderr, "benchmarks:\n");
    fprintf(stderr, "%lf initialization\n", bm_get("enc0"));
    fprintf(stderr, "%lf computing rP\n", bm_get("rP1") - bm_get("rP0"));
    fprintf(stderr, "%lf first part of map_to_point\n", bm_get("mtp1") - bm_get("mtp0"));
    fprintf(stderr, "%lf make_order_q\n", bm_get("mtp2") - bm_get("mtp1"));
    fprintf(stderr, "%lf miller\n", bm_get("miller1") - bm_get("miller0"));
    fprintf(stderr, "%lf Tate power\n", bm_get("gidr0") - bm_get("miller1"));
    fprintf(stderr, "%lf gid^r\n", bm_get("gidr1") - bm_get("gidr0"));

    fprintf(stderr, "elapsed time: %lf\n", bm_get("enc1"));
}

void bm_report_decrypt()
{
    fprintf(stderr, "dec time: %lf\n", bm_get("dec1") - bm_get("dec0"));
    fprintf(stderr, "ibe-encrypt time: %lf\n", bm_get("ibe-encrypt1") - bm_get("ibe-encrypt0"));
    fprintf(stderr, "ibe-decrypt time: %lf\n", bm_get("ibe-decrypt1") - bm_get("ibe-decrypt0"));
    fprintf(stderr, "sign time: %lf\n", bm_get("sign1") - bm_get("sign0"));
    fprintf(stderr, "verify time: %lf\n", bm_get("verify1") - bm_get("verify0"));
}
