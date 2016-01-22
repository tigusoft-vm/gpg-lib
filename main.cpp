#include <cstdio>
#include <iostream>
#include <gpgme.h>
#include <fcntl.h> // TODO

int main(int argc, char **argv) {
	gpgme_ctx_t ctx;
	gpgme_error_t ec;
	gpgme_new(&ctx);

	gpgme_data_t data_file;
	//FILE *dataFileDescriptor;
	//fopen("test.txt", "r");
	int dataFileDescriptor = open("test.txt", O_RDONLY);
	std::cout << "dataFileDescriptor " << dataFileDescriptor << std::endl;
	ec = gpgme_data_new_from_fd(&data_file, dataFileDescriptor);
	std::cout << "error " << ec << std::endl;

	gpgme_data_t sig_file;
	//FILE *sigFileDescriptor;
	//fopen("test.txt.sig", "r");
	int sigFileDescriptor = open("test.txt.sig", O_RDONLY);
	std::cout << "sigFileDescriptor " << sigFileDescriptor << std::endl;
	ec = gpgme_data_new_from_fd(&sig_file, sigFileDescriptor);
	std::cout << "error " << ec << std::endl;

	ec = gpgme_op_verify(ctx, sig_file, data_file, nullptr);
	std::cout << "error " << ec << std::endl;

	gpgme_release(ctx);
    return 0;
}
