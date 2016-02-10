#include "gtest/gtest.h"
#include "c_gpgme.hpp"

#include <string>

#define TEST_KEY_FINGERPRINT "06296DBD8E28E88516DD09871709B3F77E568FB0"
#define BAD_FINGERPRINT_1 "61F57C7FC4B08E7A87C773B567CEC2751A93A251"
#define BAD_FINGERPRINT_2 "323574F745C4794C23AB371784F3A03740B97DB2"
#define BAD_FINGERPRINT_3 "8C1CF160FBF5B76C17B1EAAD0B7F0E341C5A23D3"


TEST(detached_verify, good_signature) {
	c_gpgme gpgme;
	EXPECT_NO_THROW(gpgme.load_public_key("detached_sig/test_key.pub"));
	ASSERT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
	for (int i = 0; i < 100; ++i) {
		std::string data_filename("detached_sig/file" + std::to_string(i));
		std::string sig_filename(data_filename + ".sig");
		EXPECT_TRUE(gpgme.verify_detached_signature(sig_filename, data_filename, TEST_KEY_FINGERPRINT));
	}
	EXPECT_NO_THROW(gpgme.remove_key_from_keyring(TEST_KEY_FINGERPRINT));
	ASSERT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
}

TEST(detached_verify, bad_fingerprint) {
	c_gpgme gpgme;
	EXPECT_NO_THROW(gpgme.load_public_key("detached_sig/test_key.pub"));
	ASSERT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
	for (int i = 0; i < 100; ++i) {
		std::string data_filename("detached_sig/file" + std::to_string(i));
		std::string sig_filename(data_filename + ".sig");
		EXPECT_FALSE(gpgme.verify_detached_signature(sig_filename, data_filename, BAD_FINGERPRINT_1));
		EXPECT_FALSE(gpgme.verify_detached_signature(sig_filename, data_filename, BAD_FINGERPRINT_2));
		EXPECT_FALSE(gpgme.verify_detached_signature(sig_filename, data_filename, BAD_FINGERPRINT_3));
	}
	EXPECT_NO_THROW(gpgme.remove_key_from_keyring(TEST_KEY_FINGERPRINT));
	ASSERT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
}

TEST(detached_verify, load_non_existent_file) {
	c_gpgme gpgme;
	EXPECT_NO_THROW(gpgme.load_public_key("detached_sig/test_key.pub"));
	EXPECT_THROW(gpgme.verify_detached_signature("bad_sig_filename", "bad_data_filename", TEST_KEY_FINGERPRINT), std::runtime_error);
	EXPECT_NO_THROW(gpgme.remove_key_from_keyring(TEST_KEY_FINGERPRINT));
}


/*****************************************************************************/


TEST(pub_key, remove_public_key) {
	c_gpgme gpgme;
	EXPECT_NO_THROW(gpgme.load_public_key("detached_sig/test_key.pub"));
	ASSERT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
	EXPECT_NO_THROW(gpgme.remove_key_from_keyring(TEST_KEY_FINGERPRINT));
	EXPECT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
}

TEST(pub_key, double_remove_public_key) {
	c_gpgme gpgme;
	EXPECT_NO_THROW(gpgme.load_public_key("detached_sig/test_key.pub"));
	ASSERT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
	EXPECT_NO_THROW(gpgme.remove_key_from_keyring(TEST_KEY_FINGERPRINT));
	EXPECT_EQ(gpgme.get_last_error(), GPG_ERR_NO_ERROR);

	EXPECT_THROW(gpgme.remove_key_from_keyring(TEST_KEY_FINGERPRINT), std::runtime_error);
	EXPECT_NE(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
}

TEST(pub_key, load_non_existent_key) {
	c_gpgme gpgme;
	EXPECT_THROW(gpgme.load_public_key("detached_sig/non_existent_file.pub"), std::runtime_error);
}

TEST(pub_key, remove_non_existent_key) {
	c_gpgme gpgme;
	EXPECT_THROW(gpgme.remove_key_from_keyring(BAD_FINGERPRINT_1), std::runtime_error);
	EXPECT_NE(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
	EXPECT_THROW(gpgme.remove_key_from_keyring(BAD_FINGERPRINT_2), std::runtime_error);
	EXPECT_NE(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
	EXPECT_THROW(gpgme.remove_key_from_keyring(BAD_FINGERPRINT_3), std::runtime_error);
	EXPECT_NE(gpgme.get_last_error(), GPG_ERR_NO_ERROR);
}