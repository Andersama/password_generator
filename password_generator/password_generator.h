#pragma once
// password_generator.h : Include file for standard system include files,
// or project specific include files.

#include <iostream>
#include <string>
#include <string_view>
#include <charconv>
#include <array>

#include <openssl/ssl.h>
#include <openssl/decoder.h>
#include <openssl/encoder.h>

namespace password_generator {

	struct clear_string : std::string {
		constexpr void clear() noexcept
		{
			size_t cap = capacity();
			char*  dat = data();
			for (size_t x = 0; x < cap; x++) {
				dat[x] = 0;
			}
			std::string::clear();
		}

		~clear_string()
		{
			clear();
		}
	};

	enum class generate_password_flags {
		use_lowercase = 1 << 0,
		no_lowercase  = 1 << 1,

		use_uppercase = 1 << 2,
		no_uppercase  = 1 << 3,

		use_digits = 1 << 4,
		no_digits  = 1 << 5,

		use_symbols = 1 << 6,
		no_symbols  = 1 << 7
	};

	enum class generate_password_result {
		ok   = 0,
		fail = 1,
		fail_master_password_too_short,
		fail_no_suitable_password_encoder
	};

	struct generate_password_options {
		uint64_t seed       = 0;
		uint32_t min_length = 8;
		uint32_t max_length = 32;

		uint32_t flags = ((uint32_t)generate_password_flags::use_lowercase |
						  (uint32_t)generate_password_flags::use_uppercase |
						  (uint32_t)generate_password_flags::use_digits |
						  (uint32_t)generate_password_flags::use_symbols);
	};

	const std::string_view lowercase = "abcdefghijklmnopqrstuvwxyz";
	const std::string_view uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const std::string_view digits    = "0123456789";
	const std::string_view symbols   = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

	struct password_output {
		generate_password_result result = generate_password_result::ok;
		clear_string             password;
	};

	inline uint32_t classify_password(std::string_view password) noexcept
	{
		uint32_t out_char_flags = {0};
		for (size_t i = 0; i < password.size(); i++) {
			char character = password[i];
			// branchless comparison / flags of different character classes
			uint32_t char_flags =
							((character >= 'a' && character <= 'z') *
											(uint32_t)generate_password_flags::use_lowercase) |
							((character >= 'A' && character <= 'Z') *
											(uint32_t)generate_password_flags::use_uppercase) |
							((character >= '0' && character <= '9') * (uint32_t)generate_password_flags::use_digits);

			for (size_t s = 0; s < symbols.size(); s++) {
				char_flags |= ((symbols[s] == character) * (uint32_t)generate_password_flags::use_symbols);
			}
			out_char_flags |= char_flags;
		}
		return out_char_flags;
	}

	template<typename T> inline void monotonic_increment(T& value)
	{
		value = (value < (value + 1)) ? value + 1 : value;
	}

	void generate_password(password_output& output, std::string_view salt, std::string_view login,
					std::string_view master_password, const generate_password_options& options)
	{
		output.result = generate_password_result::fail;
		output.password.clear();

		if (master_password.size() < 8) {
			output.result = generate_password_result::fail_master_password_too_short;
			return;
		}

		const size_t max_password_size = std::max(options.min_length, options.max_length);
		const size_t min_password_size = std::min(options.min_length, options.min_length);

		const size_t tmp_buffer_size = 8096;

		const size_t hash_me_size = (salt.size() + login.size() + master_password.size() + 2 + 2 + 64) * 2;

		output.password.reserve(hash_me_size + max_password_size + tmp_buffer_size);

		output.password.append(salt.data(), salt.size());
		output.password.append(">+", 2);
		output.password.append(login.data(), login.size());
		output.password.append("#$", 2);
		output.password.append(master_password.data(), master_password.size());

		size_t num_offset     = output.password.size() + 1;
		size_t end_num_offset = output.password.size() + 1 + 32;

		output.password.append("{________________________________}", 34);

		size_t end_size = output.password.size();

		std::to_chars(output.password.data() + num_offset, output.password.data() + end_num_offset, options.seed);

		// SHA3-512 hash the combined string
		std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> m_context(EVP_MD_CTX_new(), EVP_MD_CTX_free);
		const EVP_MD*                                           m_algorithm = EVP_get_digestbyname("SHA3-512");

		if (EVP_DigestInit_ex(m_context.get(), m_algorithm, nullptr) == 0) {
			output.password.clear();
			return;
			// throw std::runtime_error("Cannot initialize hash algorithm");
		}

		int digest_length = EVP_MD_get_size(m_algorithm);
		if (digest_length <= 0) {
			output.password.clear();
			return;
		}

		size_t           remaining   = end_size;
		constexpr size_t buffer_size = 65536;
		// std::array<char, buffer_size> buffer;

		while (remaining) {
			size_t read_size      = std::min(remaining, buffer_size);
			size_t current_offset = end_size - remaining;
			remaining -= read_size;

			if (EVP_DigestUpdate(m_context.get(), output.password.data() + current_offset, read_size) == 0) {
				output.password.clear();
				return;
			}
		}

		unsigned int digest_size;
		if (EVP_DigestFinal_ex(m_context.get(), (unsigned char*)(output.password.data() + end_size), &digest_size) !=
						1) {
			output.password.clear();
			return;
		}

		// Make the hash our new string
		output.password.assign(output.password.data() + end_size, digest_length);

		// Use various base encodings to generate the resulting password

		std::array<char, 256> encode_alphabet = {};
		std::array<char, 256> decode_alphabet = {};
		uint32_t              idx             = 0;

		if (options.flags & (uint32_t)generate_password_flags::use_lowercase) {
			for (size_t c = 0; c < lowercase.size(); c++) {
				encode_alphabet[idx++] = lowercase[c];
			}
		}

		if (options.flags & (uint32_t)generate_password_flags::use_uppercase) {
			for (size_t c = 0; c < uppercase.size(); c++) {
				encode_alphabet[idx++] = uppercase[c];
			}
		}

		if (options.flags & (uint32_t)generate_password_flags::use_digits) {
			for (size_t c = 0; c < digits.size(); c++) {
				encode_alphabet[idx++] = digits[c];
			}
		}

		if (options.flags & (uint32_t)generate_password_flags::use_symbols) {
			for (size_t c = 0; c < symbols.size(); c++) {
				encode_alphabet[idx++] = symbols[c];
			}
		}

		for (size_t c = 0; c < decode_alphabet.size(); c++) {
			decode_alphabet[c] = 0xff;
		}

		for (size_t c = 0; c < idx; c++) {
			decode_alphabet[encode_alphabet[c]] = c;
		}

		const uint32_t alphabet_size = idx;
		const uint32_t clzeros       = std::countl_zero(alphabet_size);

		const uint32_t mx_shift = clzeros;
		const uint32_t mn_shift = clzeros + 1;

		const uint32_t mx_bits_shift = 32 - mx_shift;
		const uint32_t mn_bits_shift = 32 - mn_shift;

		uint32_t tmp_buf      = 0;
		uint32_t tmp_buf_bits = 0;
		size_t   i            = 0;
		size_t   out_i        = 0;
		for (; i < output.password.size(); i++) {
			// load a byte into the buffer (8 bits)
			uint8_t v = output.password[i];
			tmp_buf   = (tmp_buf << 8) | v;
			tmp_buf_bits += 8;

			do {
				uint32_t lop_off = tmp_buf << (32 - tmp_buf_bits);
				uint32_t h_value = (lop_off >> mx_shift);
				uint32_t l_value = (lop_off >> mn_shift);

				uint32_t e_bits  = (h_value >= idx) ? mn_bits_shift : mx_bits_shift;
				uint32_t e_value = (h_value >= idx) ? l_value : h_value;

				tmp_buf_bits -= e_bits;

				output.password.data()[output.password.size() + out_i] = encode_alphabet[e_value];
				out_i++;
			} while (tmp_buf_bits >= mx_bits_shift);
		}

		output.password.assign(output.password.data() + output.password.size(), out_i);

		size_t           idx_to_check = (output.password.size() - options.max_length);
		std::string_view current_password{output.password.data(), output.password.size()};

		std::cout << current_password << '\n';

		uint32_t since_lowercase = uint32_t{0xffffffff};
		uint32_t since_uppercase = uint32_t{0xffffffff};
		uint32_t since_digit     = uint32_t{0xffffffff};
		uint32_t since_symbol    = uint32_t{0xffffffff};

		for (size_t idx = 0; idx < output.password.size(); idx++) {
			monotonic_increment(since_lowercase);
			monotonic_increment(since_uppercase);
			monotonic_increment(since_digit);
			monotonic_increment(since_symbol);

			// categorize the password character into exclusive groups
			std::string_view potential_password_char =
							std::string_view{current_password.data() + idx, 1}; // current_password.substr(idx, 1);
			uint32_t char_flags = classify_password(potential_password_char);

			// reset the counts if any of the flags are set
			since_lowercase = (char_flags & (uint32_t)generate_password_flags::use_lowercase) ? 0 : since_lowercase;
			since_uppercase = (char_flags & (uint32_t)generate_password_flags::use_uppercase) ? 0 : since_uppercase;
			since_digit     = (char_flags & (uint32_t)generate_password_flags::use_digits) ? 0 : since_digit;
			since_symbol    = (char_flags & (uint32_t)generate_password_flags::use_symbols) ? 0 : since_symbol;

			// combine counts back into an aggregated bitset
			uint32_t aggregate_flags =
							((since_lowercase < options.max_length) *
											(uint32_t)generate_password_flags::use_lowercase) |
							((since_uppercase < options.max_length) *
											(uint32_t)generate_password_flags::use_uppercase) |
							((since_digit < options.max_length) * (uint32_t)generate_password_flags::use_digits) |
							((since_symbol < options.max_length) * (uint32_t)generate_password_flags::use_symbols);

			// check if the bitset is satisfied and that we're at least max_length characters
			if ((aggregate_flags & options.flags) == options.flags && !(idx < options.max_length)) {
				output.result = generate_password_result::ok;
				output.password.assign(output.password.data() + (idx - options.max_length), options.max_length);
				return;
			}
		}

		output.password.clear();
		return;
	}
} // namespace password_generator