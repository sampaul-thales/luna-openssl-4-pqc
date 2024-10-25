/**
 * Copyright (C) 2016 SafeNet, Inc. All rights reserved.
 *
 * This program can be used to simulate a forking application using the OpenSSL gem engine.  The program
 * forks the specified amount of times before the child process performs the crypto operations.
 * The number of crypto operations is specified as well as the value for IntermediateProcesses.
 * This program can be used to see the performance differences when the IntermediateProcesses matches
 * the level of forking.
 *
 * To compile:
 *   gcc -lcrypto -I../engine -o forking forking.c
 *
 * Before running, create an RSA key using sautil and have the tmpkey.pem file in the CWD.
 */

#include <openssl/engine.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include "e_gem.h"

#define PEM_FILE "tmpkey.pem"

#define EXIT_FAILURE 1

int forks = 2;
int operations = 100;
int childs = 1;
char *intermediate_processes = NULL;

ENGINE* load_engine() {
	ENGINE *e = NULL;
	ENGINE_load_builtin_engines();
	if ((e = ENGINE_by_id("gem")) == NULL) {
		fprintf(stderr, "Unable to get gem engine.\n");
	goto err;
	}

	const char *eid = ENGINE_get_id(e);
	printf("Engine id: %s\n", eid);

	if (ENGINE_set_default(e, 1) != 1)
	{
	fprintf(stderr, "Unable to set engine default.\n");
		goto err;
	}
	if (intermediate_processes != NULL) {
		if (ENGINE_ctrl_cmd_string(e, "IntermediateProcesses", intermediate_processes, 0) != 1) {
			fprintf(stderr, "WARNING: failed to set \"IntermediateProcesses=1\". \n");
		}
	}
	if (ENGINE_init(e) != 1)
	{
		fprintf(stderr, "ENGINE_init failed\n");
		goto err;
	}
	return e;
err:
	if (e != NULL)
		ENGINE_free(e);
	exit(EXIT_FAILURE);
	return NULL;
}

RSA* read_rsa_key(char *filename) {
	BIO *f = NULL;
	RSA *rsa;

	if ( (f = BIO_new(BIO_s_file())) == NULL )
	{
		fprintf(stderr, "BIO_new failed. \n");
	}

	if (BIO_read_filename(f, filename) <= 0)
	{
		fprintf(stderr, "BIO_read_filename failed. \n");
	}

	rsa = PEM_read_bio_RSAPrivateKey(f, NULL, NULL, NULL);
	if ( rsa == NULL )
	{
		fprintf(stderr, "PEM_read_bio_RSAPrivateKey failed. \n");
	}
	BIO_free(f);
	char *modulus;
	char *exp;
	modulus = BN_bn2hex(rsa->n);
	printf("Modulus:\n%s\n", modulus);

	exp = BN_bn2hex(rsa->e);
	printf("Exponent:\n%s\n", exp);
	return rsa;
}

RSA *rsa;
char *from = "Sign this.";
char sig[1024];
unsigned char hash[SHA256_DIGEST_LENGTH];
int siglen;
int child = -1;

void sha256() {
	int i;
	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, from, strlen(from));
	SHA256_Final(hash, &sha256);
	printf("Digest is: ");
	for(i = 0; i < SHA256_DIGEST_LENGTH; i++)
		printf("%02x", hash[i]);
	printf("\n");
}

void fork_n(int n) {
	int i, j;
	pid_t pid;
	int c = -1;
	for (i = 0; i < n; i++) {
		pid = fork();

		switch (pid) {
		case -1:
			fprintf(stderr, "ERROR: Unable to fork!");
			exit(EXIT_FAILURE);
			break;
		case 0: //child
			printf("Forked process pid=%d\n", (int)getpid());
			if (RSA_sign(NID_sha256, (const unsigned char *)hash, SHA256_DIGEST_LENGTH, sig, &siglen, rsa) != 1) {
				fprintf(stderr, "RSA_Sign failed.\n");
			}
			break;
		default:  //parent so exit
			exit(0);
			break;
		}
	}
}

void fork_childs() {
	int i, j;
	pid_t pid;
	int in_child = 0;
	for (i = 0; i < childs && !in_child; i++) {
		pid = fork();

		switch (pid) {
		case -1:
			fprintf(stderr, "ERROR: Unable to fork!");
			exit(EXIT_FAILURE);
			break;
		case 0: //child
			child = i+1;
			in_child = 1;
			printf("Forked child %d process pid=%d \n", i+1, (int)getpid());
			break;
		default:  //parent so check if all childs forked and exit
			if (i == childs-1)
				exit(0);
			break;
		}
	}
}

static void print_usage() {
	printf(
			"forking - Copyright (C) 2016 SafeNet, Inc. All rights reserved. \n\n"
			"Options:\n"
			"  -h                          display this output\n\n"
			"  -n <num operations>         the number of operations\n"
			"  -f <num forks>              the number of forks in application\n"
			"  -i <intermediate processes> number of intermediate processes. If not"
			"                              specified the value of IntermediateProcesses"
			"                              in Chrystoki.conf is used by the engine."
			"  -c <child processes>        number of child processes."
	);
}

static void parse_args(int argc, char *argv[]) {
	int opt;

	while ((opt = getopt(argc, argv, "n:f:i:c:h")) != -1) {
		switch (opt) {
		case 'n':
			operations = atoi(optarg);
			break;
		case 'f':
			forks = atoi(optarg);
			break;
		case 'i':
			intermediate_processes = strdup(optarg);
			break;
		case 'c':
			childs = atoi(optarg);
			break;
		case 'h':
			forks = atoi(optarg);
			break;
		default:
			print_usage();
			exit(EXIT_FAILURE);
		}
	}
}

int main(int argc, char *argv[]) {
	int i;
	struct timeval  tv1, tv2;

	parse_args(argc, argv);

	OpenSSL_add_all_algorithms();
	ENGINE *engine = load_engine();

	rsa = read_rsa_key(PEM_FILE);

	sha256();

	printf("Forking %d time(s).\n", forks);

	if (forks > 0) {
		fork_n(forks-1);
		fork_childs();
	}

	printf("Performing %d signing operations.\n", operations);

	gettimeofday(&tv1, NULL);
	for (i = 0; i < operations; i++) {
		if (RSA_sign(NID_sha256, (const unsigned char *)hash, SHA256_DIGEST_LENGTH, sig, &siglen, rsa) != 1) {
			printf("RSA_Sign failed.\n");
		}
	}
	gettimeofday(&tv2, NULL);

	printf("Elapsed time child=%d: %f (s)\n", child, (double) (tv2.tv_usec - tv1.tv_usec) / 1000000 + (double) (tv2.tv_sec - tv1.tv_sec));
	printf("Cleaning engine.\n");
	ENGINE_free(engine);
	ENGINE_finish(engine);
	ENGINE_cleanup();

	return 0;
}
