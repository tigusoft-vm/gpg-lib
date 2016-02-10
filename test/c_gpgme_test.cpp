#include "gtest/gtest.h"
#include "c_gpgme.hpp"

#include <string>

#define TEST_KEY_FINGERPRINT "06296DBD8E28E88516DD09871709B3F77E568FB0"
#define BAD_FINGERPRINT_1 "61F57C7FC4B08E7A87C773B567CEC2751A93A252"
#define BAD_FINGERPRINT_2 "323574F745C4794C23AB371784F3A03740B97DB9"
#define BAD_FINGERPRINT_3 "8C1CF160FBF5B76C17B1EAAD0B7F0E341C5A23D2"


TEST(detached_verify, good_signature) {
	c_gpgme gpgme;
	gpgme.load_public_key("detached_sig/test_key.pub");
	ASSERT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
	for (int i = 0; i < 100; ++i) {
		std::string data_filename("detached_sig/file" + std::to_string(i));
		std::string sig_filename(data_filename + ".sig");
		EXPECT_TRUE(gpgme.verify_detached_signature(sig_filename, data_filename, TEST_KEY_FINGERPRINT));
	}
	gpgme.remove_key_from_keyring(TEST_KEY_FINGERPRINT);
}

TEST(detached_verify, bad_fingerprint) {
	c_gpgme gpgme;
	gpgme.load_public_key("detached_sig/test_key.pub");
	ASSERT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
	for (int i = 0; i < 100; ++i) {
		std::string data_filename("detached_sig/file" + std::to_string(i));
		std::string sig_filename(data_filename + ".sig");
		EXPECT_FALSE(gpgme.verify_detached_signature(sig_filename, data_filename, BAD_FINGERPRINT_1));
		EXPECT_FALSE(gpgme.verify_detached_signature(sig_filename, data_filename, BAD_FINGERPRINT_2));
		EXPECT_FALSE(gpgme.verify_detached_signature(sig_filename, data_filename, BAD_FINGERPRINT_3));
	}
	gpgme.remove_key_from_keyring(TEST_KEY_FINGERPRINT);
}