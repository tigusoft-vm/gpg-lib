#include "c_gpgme.hpp"

#include <cassert>
#include <fcntl.h>
#include <stdexcept>

c_gpgme::c_gpgme() {
	setlocale (LC_ALL, "");
	gpgme_set_locale(NULL, LC_CTYPE, setlocale (LC_CTYPE, NULL));
	gpgme_check_version(NULL);
	m_error_code = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);

	m_error_code = gpgme_new(&m_ctx);
	assert(m_ctx != nullptr);
}

gpgme_data_t c_gpgme::load_file ( const std::string &filename ) {
	gpgme_data_t data_file = nullptr;
#ifdef __linux__
	int file_descriptor = open(filename.c_str(), O_RDONLY); // TODO
	if (file_descriptor == -1) {
		throw std::runtime_error(std::string("cannot open file ") + filename);
	}
#endif
	m_error_code = gpgme_data_new_from_fd(&data_file, file_descriptor);
	
	return data_file;
}


c_gpgme::~c_gpgme() {
	gpgme_release(m_ctx);
}
