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


bool c_gpgme::verify_detached_signature ( const std::string &sig_file, const std::string &clear_data_file ) {
	try {
		auto sig_file_ptr = load_file(sig_file);
		auto clear_data_file_ptr = load_file(clear_data_file);
		m_error_code = gpgme_op_verify(m_ctx, *sig_file_ptr, *clear_data_file_ptr, nullptr);
		if (m_error_code) return false;
		gpgme_verify_result_t result = gpgme_op_verify_result(m_ctx);
		if (result == nullptr) return false;
		gpgme_signature_t sig = result->signatures;
		if (!sig) return false;

		for (; sig; sig = sig->next) {
			if ((sig->summary & GPGME_SIGSUM_VALID) || (sig->summary & GPGME_SIGSUM_GREEN)) {  // Valid
				return true;
			}
		}
		return false;
	}
	catch(std::exception e) {
		return false;
	}
}


std::unique_ptr<gpgme_data_t, std::function<void(gpgme_data_t *)>> c_gpgme::load_file ( const std::string &filename ) {
	auto deleter = [](gpgme_data_t *ptr) {
		gpgme_data_release(*ptr);
		delete ptr;
	};
	std::unique_ptr<gpgme_data_t, std::function<void(gpgme_data_t *)>> data_file_ptr(new gpgme_data_t, deleter);
#ifdef __linux__ // TODO windows
	int file_descriptor = open(filename.c_str(), O_RDONLY);
	if (file_descriptor == -1) {
		throw std::runtime_error(std::string("cannot open file ") + filename);
	}
#endif
	m_error_code = gpgme_data_new_from_fd(data_file_ptr.get(), file_descriptor);
	if (m_error_code) {
		throw std::runtime_error(std::string("load file error, error code ") + std::to_string(m_error_code));
	}
	return data_file_ptr;
}


c_gpgme::~c_gpgme() {
	gpgme_release(m_ctx);
}
