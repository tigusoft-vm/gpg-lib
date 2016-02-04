#include "c_gpgme.hpp"

#include <cassert>

c_gpgme::c_gpgme() {
	setlocale (LC_ALL, "");
	gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
	gpgme_check_version(NULL);
	m_error_code = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

	m_error_code = gpgme_new(&m_ctx);
	assert(m_ctx != nullptr);
}

