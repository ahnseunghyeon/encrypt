/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <err.h>
#include <stdio.h>
#include <string.h>

/* OP-TEE TEE client API (built by optee_client) */
#include <tee_client_api.h>

/* To the the UUID (found the the TA's h-file(s)) */
#include <TEEencrypt_ta.h>

#define RSA_KEY_SIZE 1024
#define RSA_MAX_PLAIN_LEN_1024 86 // (1024/8) - 42 (padding)
#define RSA_CIPHER_LEN_1024 (RSA_KEY_SIZE / 8)



int main(int argc, char* argv[])
{
	//struct ta_attrs ta;
	//char clear[RSA_MAX_PLAIN_LEN_1024];
	//char ciph[RSA_CIPHER_LEN_1024];

	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID uuid = TA_TEEencrypt_UUID;
	uint32_t err_origin;
	char plaintext[64] = {0,};
	char ciphertext[64] = {0,};
	int len=64;
	int cipherkey=0;
	FILE *fp;
	char buffer[100] = {0,};


	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed with code 0x%x", res);

	
	res = TEEC_OpenSession(&ctx, &sess, &uuid,
			       TEEC_LOGIN_PUBLIC, NULL, NULL, &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_Opensession failed with code 0x%x origin 0x%x",
			res, err_origin);

	
	memset(&op, 0, sizeof(op));

	
	//TEEC_VALUE_INOUT
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT, TEEC_VALUE_INOUT,
					 TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = plaintext;
	op.params[0].tmpref.size = len;
	op.params[1].value.a = 0;
	
	printf("%d",op.params[1].value.a);

	if(strcmp(argv[1], "-e")==0){
	
	fp = fopen(argv[2], "r");
	fread(buffer,1,sizeof(buffer),fp);

	fclose(fp);

	printf("========================Encryption========================\n");
	memcpy(op.params[0].tmpref.buffer, buffer, len);

	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_ENCRYPT, &op,
				 &err_origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	
	memcpy(ciphertext, op.params[0].tmpref.buffer, len);
	

	fp = fopen("encrypt.txt", "w");
	fputs(ciphertext,fp);
	fclose(fp);
	printf("Ciphertext : %s\n", ciphertext);
	
	
	fp = fopen("key.txt", "w");
	fprintf(fp,"%d",op.params[1].value.a);
	fclose(fp);
	printf("Cipherkey : %d\n", op.params[1].value.a);
	}

	if(strcmp(argv[1], "-d")==0){
	printf("========================Decryption========================\n");	
	fp = fopen(argv[2],"r");
	fread(buffer,1,100,fp);

	fclose(fp);
	
	fp = fopen(argv[3],"r");
	fscanf(fp,"%d",&cipherkey);

	fclose(fp);

	
	memcpy(op.params[0].tmpref.buffer, buffer, len);
	op.params[1].value.a = cipherkey;
	res = TEEC_InvokeCommand(&sess, TA_TEEencrypt_CMD_DECRYPT, &op,
				 &err_origin);
	
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InvokeCommand failed with code 0x%x origin 0x%x",
			res, err_origin);
	memcpy(plaintext, op.params[0].tmpref.buffer, len);
	
	printf("Plaintext : %s\n", plaintext);

	fp = fopen("decrypt.txt", "w");
	fputs(plaintext,fp);
	fclose(fp);
	printf("plaintext : %s\n", plaintext);
	
	}

	//rsa here
	/*printf("\nType something to be encrypted and decrypted in the TA:\n");
	
	fp = fopen(argv[2], "r");
	fread(buffer,1,sizeof(buffer),fp);

	fclose(fp);
	
	rsa_gen_keys(&ta);
	rsa_encrypt(&ta, clear, RSA_MAX_PLAIN_LEN_1024, ciph, RSA_CIPHER_LEN_1024);*/
	

	TEEC_CloseSession(&sess);

	TEEC_FinalizeContext(&ctx);

	return 0;
}
