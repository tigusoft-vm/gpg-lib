#ifndef C_GPGME_H
#define C_GPGME_H

#include <gpgme.h>
#include <string>

class c_gpgme
{
	public:
		c_gpgme();
		c_gpgme(const c_gpgme &) = delete;
		c_gpgme(c_gpgme &&) = delete;
		c_gpgme & operator=(const c_gpgme &) = delete;
		c_gpgme & operator=(c_gpgme &&) = delete;

		~c_gpgme();
	private:
		gpgme_ctx_t m_ctx = nullptr;
		gpgme_error_t m_error_code;

};

#endif // C_GPGME_H
