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

	ec = gpgme_new(&ctx);

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
		std::cout << "verify ok" << std::endl;


	// free
	gpgme_data_release(data_file);
	gpgme_data_release(sig_file);
	gpgme_data_release(pub_key);
	gpgme_release(ctx);

	return 0;
}

int main3()
{
   char *p;
   char buf[SIZE];
   size_t read_bytes;
   int tmp;
   gpgme_ctx_t ceofcontext;
   gpgme_error_t err;
   gpgme_data_t data;

   gpgme_engine_info_t enginfo;



   /* The function `gpgme_check_version' must be called before any other
    * function in the library, because it initializes the thread support
    * subsystem in GPGME. (from the info page) */
   setlocale (LC_ALL, "");
   p = (char *) gpgme_check_version(NULL);
   printf("version=%s\n",p);
   /* set locale, because tests do also */
   gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));

   /* check for OpenPGP support */
   err = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
   if(err != GPG_ERR_NO_ERROR) return 1;

   p = (char *) gpgme_get_protocol_name(GPGME_PROTOCOL_OpenPGP);
   printf("Protocol name: %s\n",p);

   /* get engine information */
   err = gpgme_get_engine_info(&enginfo);
   if(err != GPG_ERR_NO_ERROR) return 2;
   printf("file=%s, home=%s\n",enginfo->file_name,enginfo->home_dir);
#if 0
#endif


   /* create our own context */
   err = gpgme_new(&ceofcontext);
   if(err != GPG_ERR_NO_ERROR) return 3;

#if 0

   /* set protocol to use in our context */
   err = gpgme_set_protocol(ceofcontext,GPGME_PROTOCOL_OpenPGP);
   if(err != GPG_ERR_NO_ERROR) return 4;

   /* set engine info in our context; I changed it for ceof like this:

   err = gpgme_ctx_set_engine_info (ceofcontext, GPGME_PROTOCOL_OpenPGP,
               "/usr/bin/gpg","/home/user/nico/.ceof/gpg/");

      but I'll use standard values for this example: */

   err = gpgme_ctx_set_engine_info (ceofcontext, GPGME_PROTOCOL_OpenPGP,
               enginfo->file_name,enginfo->home_dir);
   if(err != GPG_ERR_NO_ERROR) return 5;

   /* do ascii armor data, so output is readable in console */
   gpgme_set_armor(ceofcontext, 1);

   /* create buffer for data exchange with gpgme*/
   err = gpgme_data_new(&data);
   if(err != GPG_ERR_NO_ERROR) return 6;

   /* set encoding for the buffer... */
   err = gpgme_data_set_encoding(data,GPGME_DATA_ENCODING_ARMOR);
   if(err != GPG_ERR_NO_ERROR) return 7;

   /* verify encoding: not really needed */
   tmp = gpgme_data_get_encoding(data);
   if(tmp == GPGME_DATA_ENCODING_ARMOR) {
      printf("encode ok\n");
   } else {
      printf("encode broken\n");
   }

   /* with NULL it exports all public keys */
   err = gpgme_op_export(ceofcontext,NULL,0,data);
   if(err != GPG_ERR_NO_ERROR) return 8;

   read_bytes = gpgme_data_seek (data, 0, SEEK_END);
   printf("end is=%d\n",read_bytes);
   if(read_bytes == -1) {
      p = (char *) gpgme_strerror(errno);
      printf("data-seek-err: %s\n",p);
      return 9;
   }
   read_bytes = gpgme_data_seek (data, 0, SEEK_SET);
   printf("start is=%d (should be 0)\n",read_bytes);

   /* write keys to stderr */
   while ((read_bytes = gpgme_data_read (data, buf, SIZE)) > 0) {
      write(2,buf,read_bytes);
   }
   /* append \n, so that there is really a line feed */
   write(2,"\n",1);

   /* free data */
   gpgme_data_release(data);

#endif


   /* free context */
   gpgme_release(ceofcontext);

   return 0;
}







int main2(int argc, char **argv) {
	gpgme_error_t ec;

	gpgme_ctx_t ctx = (gpgme_context*) malloc( sizeof(gpgme_ctx_t) );
	gpgme_new(&ctx);
	gpgme_release(ctx);

/*	gpgme_data_t data_file;
	//FILE *dataFileDescriptor;
	//fopen("test.txt", "r");
	int dataFileDescriptor = open("test.txt", O_RDONLY);
	std::cout << "dataFileDescriptor " << dataFileDescriptor << std::endl;
	ec = gpgme_data_new_from_fd(&data_file, dataFileDescriptor);
	std::cout << "error " << ec << std::endl;*/
/*
	gpgme_data_t sig_file;
	//FILE *sigFileDescriptor;
	//fopen("test.txt.sig", "r");
	int sigFileDescriptor = open("test.txt.sig", O_RDONLY);
	std::cout << "sigFileDescriptor " << sigFileDescriptor << std::endl;
	ec = gpgme_data_new_from_fd(&sig_file, sigFileDescriptor);
	std::cout << "error " << ec << std::endl;

	ec = gpgme_op_verify_start(ctx, sig_file, nullptr, data_file);
	std::cout << "error " << ec << std::endl;

	gpgme_wait()

	ec = gpgme_op_verify(ctx, sig_file, nullptr, data_file);
	std::cout << "error " << ec << std::endl;
*/
    return 0;
}
