#include <cstdio>
#include <iostream>
#include <gpgme.h>

int main(int argc, char **argv) {
	gpgme_ctx_t ctx;
	gpgme_new(&ctx);

	gpgme_data_t data_file;
	FILE *dataFileDescriptor;
	fopen("test.txt", "r");
	gpgme_data_new_from_fd(&data_file, fileno(dataFileDescriptor));

	gpgme_data_t sig_file;
	FILE *sigFileDescriptor;
	fopen("test.txt.sig", "r");
	gpgme_data_new_from_fd(&sig_file, fileno(sigFileDescriptor));

	gpgme_op_verify(ctx, sig_file, data_file, nullptr);
	gpgme_release(ctx);
    return 0;
}
