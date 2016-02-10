#include "c_gpgme.hpp"

#include <boost/filesystem.hpp>
#include <cassert>
#include <fcntl.h>
#include <stdexcept>


#ifdef __CYGWIN__
#include <sstream>
namespace std {
template <typename T>
std::string to_string(T val) {
    std::stringstream stream;
    stream << val;
    return stream.str();
}
} // namespace std
#endif

c_gpgme::c_gpgme() {
	setlocale (LC_ALL, "");
	gpgme_set_locale(nullptr, LC_CTYPE, setlocale (LC_CTYPE, nullptr));
	gpgme_check_version(nullptr);
	m_error_code = gpgme_engine_check_version(GPGME_PROTOCOL_OpenPGP);
	m_error_code = gpgme_new(&m_ctx);
	assert(m_ctx != nullptr);
#ifdef __CYGWIN__
	m_error_code = gpgme_ctx_set_engine_info (m_ctx, GPGME_PROTOCOL_OpenPGP,
               "./gpg.exe", nullptr);
#endif
}


bool c_gpgme::verify_detached_signature ( const std::string &sig_file, const std::string &clear_data_file, const std::string &expected_fpr ) {
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
			if (expected_fpr == sig->fpr) return true;
			else return false;
		}
		else if (sig->summary == 0 && sig->status == GPG_ERR_NO_ERROR) { // Valid but key is not certified with a trusted signature
			if (expected_fpr == sig->fpr) return true;
			else return false;
		}
	}
	return false;
}


std::unique_ptr<gpgme_data_t, std::function<void(gpgme_data_t *)>> c_gpgme::load_file ( const std::string &filename ) {
	if (!boost::filesystem::exists(filename)) {
		throw std::runtime_error(std::string("file not exists"));
	}
	auto deleter = [](gpgme_data_t *ptr) {
		gpgme_data_release(*ptr);
		delete ptr;
	};
	std::unique_ptr<gpgme_data_t, std::function<void(gpgme_data_t *)>> data_file_ptr(new gpgme_data_t, deleter);
	int file_descriptor = open(filename.c_str(), O_RDONLY);
	if (file_descriptor == -1) {
		throw std::runtime_error(std::string("cannot open file ") + filename);
	}
	m_error_code = gpgme_data_new_from_fd(data_file_ptr.get(), file_descriptor);
	if (m_error_code) {
		throw std::runtime_error(std::string("load file error, error code ") + std::to_string(m_error_code));
	}
	return data_file_ptr;
}


void c_gpgme::remove_key_from_keyring ( const std::string &fingerprint ) {
	gpgme_key_t key;
	m_error_code = gpgme_get_key(m_ctx, fingerprint.c_str(), &key, 0);

	if (m_error_code != GPG_ERR_NO_ERROR) {
		throw std::runtime_error(gpgme_strsource(m_error_code));
	}

	m_error_code = gpgme_op_delete(m_ctx, key, 0);

	if (m_error_code != GPG_ERR_NO_ERROR) {
		throw std::runtime_error(gpgme_strsource(m_error_code));
	}
}


void c_gpgme::load_public_key ( const std::string &filename ) {
	auto key_file_ptr = load_file(filename);
	m_error_code = gpgme_op_import(m_ctx, *key_file_ptr);
}


gpgme_error_t c_gpgme::get_last_error() {
	return m_error_code;
}


c_gpgme::~c_gpgme() {
	gpgme_release(m_ctx);
}
