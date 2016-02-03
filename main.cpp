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

#define dbg(X) std::cout << __LINE__ << ": " << X << std::endl


bool load_public_key(const std::string &key_filename, gpgme_ctx_t &ctx) {
	dbg("load_public_key start");
	//gpgme_set_armor(ctx, 1); // XXX
	gpgme_error_t ec;
	gpgme_data_t data_file = NULL;
	int dataFileDescriptor = open(key_filename.c_str(), O_RDONLY);
	ec = gpgme_data_new_from_fd(&data_file, dataFileDescriptor);
	dbg("error " << ec);

	ec = gpgme_op_import(ctx, data_file);
	dbg("error: " << ec);

	gpgme_data_release(data_file);

	dbg("**************************");
	gpgme_import_result_t key_import_result = gpgme_op_import_result(ctx);
	dbg("considered " << key_import_result->considered);
	dbg("no_user_id " << key_import_result->no_user_id);
	dbg("imported_rsa " << key_import_result->imported_rsa);
	dbg("unchanged " << key_import_result->unchanged);
	dbg("new_user_ids " << key_import_result->new_user_ids);
	dbg("new_sub_keys " << key_import_result->new_sub_keys);
	dbg("new_signatures " << key_import_result->new_signatures);
	dbg("new_revocations " << key_import_result->new_revocations);
	dbg("secret_read " << key_import_result->secret_read);
	dbg("secret_imported " << key_import_result->secret_imported);
	dbg("secret_unchanged " << key_import_result->secret_unchanged);
	dbg("not_imported " << key_import_result->not_imported);

	dbg("**************************");

	dbg("load_public_key end");
	return true;
}

int main()
{
	gpgme_ctx_t ctx = NULL;
	gpgme_error_t ec;

	setlocale (LC_ALL, "");
	gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
	gpgme_check_version(NULL);
	ec = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
	dbg("error " << ec);

	ec = gpgme_new(&ctx);
	dbg("error " << ec);

	/* set protocol to use in our context */
	ec = gpgme_set_protocol(ctx, GPGME_PROTOCOL_OpenPGP);
	dbg("error " << ec);

	//ec = gpgme_ctx_set_engine_info (ctx, GPGME_PROTOCOL_OpenPGP,
    //           "/usr/bin/gpg","/home/robert/.gnupg/");
	//dbg("error " << ec);

	gpgme_data_t data_file = NULL;
	int dataFileDescriptor = open("test.txt", O_RDONLY);
	dbg("dataFileDescriptor " << dataFileDescriptor);
	ec = gpgme_data_new_from_fd(&data_file, dataFileDescriptor);
	dbg("error " << ec);

	gpgme_data_t sig_file = NULL;
	int sigFileDescriptor = open("test.txt.sig", O_RDONLY);
	dbg("sigFileDescriptor " << sigFileDescriptor);
	ec = gpgme_data_new_from_fd(&sig_file, sigFileDescriptor);
	dbg("error " << ec);

	// import key
	load_public_key("key.pub", ctx);

	//ec = gpgme_op_verify_start(ctx, sig_file, nullptr, data_file);
	ec = gpgme_op_verify(ctx, sig_file, nullptr, data_file);
	dbg("error " << ec);
	if (ec == GPG_ERR_INV_VALUE)
		dbg("GPG_ERR_INV_VALUE");
	else if (ec == GPG_ERR_NO_DATA)
		dbg("GPG_ERR_NO_DATA");

	dbg("verify start");
	gpgme_verify_result_t result = gpgme_op_verify_result(ctx);
	if (result == NULL)
		dbg("verify error");
	else
	{
		gpgme_signature_t sig = result->signatures;
		if (!sig)
			dbg("sig verification error");
		for (; sig; sig = sig->next) {
			if ((sig->summary & GPGME_SIGSUM_VALID) ||  // Valid
				(sig->summary & GPGME_SIGSUM_GREEN))  // Valid
			{
				dbg("SIGNATURE OK");
			}
			else if (sig->summary == 0 && sig->status == GPG_ERR_NO_ERROR) // Valid but key is not certified with a trusted signature
				dbg("SIGNATURE OK but key is not certified with a trusted signature");
			else
				dbg("SIGNATURE NOT OK, ec: " << ec);

		}
	}


	dbg("verify end, free data");
	// free
	gpgme_data_release(data_file);
	gpgme_data_release(sig_file);
	gpgme_release(ctx);

	return 0;
}

