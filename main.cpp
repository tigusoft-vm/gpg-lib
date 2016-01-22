#include <cstdio>
#include <iostream>
#include <gpgme.h>
#include <fcntl.h> // TODO



/* gpgme-example1:
 *
 *    Nico Schottelius, 2007-08-05, GPLv3
 *
 *    export all public keys
 */

#include <gpgme.h>   /* gpgme             */
#include <stdio.h>   /* printf            */
#include <unistd.h>  /* write             */
#include <errno.h>   /* errno             */
#include <locale.h>  /* locale support    */

#define SIZE 1024

/* USE -D_FILE_OFFSET_BITS=64 (at least) on Debian!  */


int main()
{
	gpgme_ctx_t ctx = NULL;
	gpgme_error_t ec;

	gpgme_check_version("");

	ec = gpgme_new(&ctx);

	/* set protocol to use in our context */
	ec = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
	std::cout << "error " << ec << std::endl;

	gpgme_data_t data_file = NULL;
	int dataFileDescriptor = open("test.txt", O_RDONLY);
	std::cout << "dataFileDescriptor " << dataFileDescriptor << std::endl;
	ec = gpgme_data_new_from_fd(&data_file, dataFileDescriptor);
	std::cout << "error " << ec << std::endl;

	gpgme_data_t sig_file = NULL;
	int sigFileDescriptor = open("test.txt.sig", O_RDONLY);
	std::cout << "sigFileDescriptor " << sigFileDescriptor << std::endl;
	ec = gpgme_data_new_from_fd(&sig_file, sigFileDescriptor);
	std::cout << "error " << ec << std::endl;

	// import key
	gpgme_data_t pub_key = NULL;
	int pub_key_desc = open("key.pub", O_RDONLY);
	std::cout << "pub_key_desc " << pub_key_desc << std::endl;
	ec = gpgme_data_new_from_fd(&pub_key, pub_key_desc);
	std::cout << "error " << ec << std::endl;

	ec = gpgme_op_import(ctx, pub_key);
	gpgme_import_result_t key_import_result = gpgme_op_import_result(ctx);

	//ec = gpgme_op_verify_start(ctx, sig_file, nullptr, data_file);
	ec = gpgme_op_verify(ctx, sig_file, nullptr, data_file);
	std::cout << "error " << ec << std::endl;
	if (ec == GPG_ERR_INV_VALUE)
		std::cout << "GPG_ERR_INV_VALUE" << std::endl;
	else if (ec == GPG_ERR_NO_DATA)
		std::cout << "GPG_ERR_NO_DATA" << std::endl;

	gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
	if (result == NULL)
		std::cout << "verify error" << std::endl;
	else
	{
		gpgme_signature_t sig = result->signatures;
		if (!sig)
			std::cout << "sig verification error" << std::endl;
		for (; sig; sig = sig->next) {
			if ((sig->summary & GPGME_SIGSUM_VALID) ||  // Valid
				(sig->summary & GPGME_SIGSUM_GREEN) ||  // Valid
				(sig->summary == 0 && sig->status == GPG_ERR_NO_ERROR)) // Valid but key is not certified with a trusted signature
				std::cout << "SIGNATURE OK" << std::endl;
		}
	}



	// free
	gpgme_data_release(data_file);
	gpgme_data_release(sig_file);
	gpgme_data_release(pub_key);
	gpgme_release(ctx);

	return 0;
}

