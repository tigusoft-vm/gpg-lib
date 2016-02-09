#ifndef C_GPGME_H
#define C_GPGME_H

#include <gpgme.h>
#include <memory>
#include <string>

class c_gpgme
{
	public:
		c_gpgme();
		c_gpgme(const c_gpgme &) = delete;
		c_gpgme(c_gpgme &&) = delete;
		c_gpgme & operator=(const c_gpgme &) = delete;
		c_gpgme & operator=(c_gpgme &&) = delete;

		/**
		 * Verify signed message. @param sig_file is detached signature file (gpg --detach-sign)
		 * @param clear_data_file is signed clear data filename.
		 */
		bool verify_detached_signature(const std::string &sig_file, const std::string &clear_data_file);

		/**
		 * Verify signed message from @param sig_file and save clear data to @param output_data_file
		 */
		//bool verify_clearsign_file(const std::string &sig_file, const std::string &output_data_file);

		void load_public_key(const std::string &filename);
		~c_gpgme();
	private:
		gpgme_ctx_t m_ctx = nullptr;
		gpgme_error_t m_error_code;

		void release_data_t(gpgme_data_t *ptr);
		std::unique_ptr<gpgme_data_t, std::function<void(gpgme_data_t *)>> load_file(const std::string &filename);

};

#endif // C_GPGME_H
