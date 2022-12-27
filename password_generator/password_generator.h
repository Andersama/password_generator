#pragma once
// password_generator.h : Include file for standard system include files,
// or project specific include files.

#include <iostream>
#include <string>
#include <string_view>
#include <charconv>
#include <array>

#include <sodium.h>

namespace pcg {
	typedef struct {
		uint64_t state;
		uint64_t inc;
	} pcg32_random_t;

	inline uint32_t pcg32_random_r(pcg32_random_t* rng) noexcept
	{
		uint64_t oldstate = rng->state;
		// Advance internal state
		rng->state = oldstate * 6364136223846793005ULL + (rng->inc | 1);
		// Calculate output function (XSH RR), uses old state for max ILP
		uint32_t xorshifted = ((oldstate >> 18u) ^ oldstate) >> 27u;
		uint32_t rot        = oldstate >> 59u;
		return (xorshifted >> rot) | (xorshifted << ((-rot) & 31));
	}

	typedef struct {
		uint64_t w_state;
		uint64_t x_state;
		uint64_t y_state;
		uint64_t z_state;
	} romu64_quad_random_t;

	typedef struct {
		uint64_t x_state;
		uint64_t y_state;
		uint64_t z_state;
	} romu64_trio_random_t;

	inline uint64_t rotl(uint64_t d, uint64_t lrot) noexcept
	{
		return ((d << (lrot)) | (d >> (8 * sizeof(d) - (lrot))));
	}

	inline uint64_t romu_trio_random_r(romu64_trio_random_t* rng) noexcept
	{
		uint64_t xp  = rng->x_state;
		uint64_t yp  = rng->y_state;
		uint64_t zp  = rng->z_state;
		rng->x_state = 15241094284759029579u * zp;
		rng->y_state = yp - xp;
		rng->y_state = ((rng->y_state << (12)) | (rng->y_state >> (8 * sizeof(rng->y_state) - (12))));
		rng->z_state = zp - yp;
		rng->z_state = ((rng->z_state << (44)) | (rng->z_state >> (8 * sizeof(rng->z_state) - (44))));
	}

	inline uint64_t romu_quad_random_r(romu64_quad_random_t* rng) noexcept
	{
		uint64_t wp = rng->w_state;
		uint64_t xp = rng->x_state;
		uint64_t yp = rng->y_state;
		uint64_t zp = rng->z_state;

		rng->w_state = 15241094284759029579u * zp; // a-mult
		rng->x_state = zp + rotl(wp, 52);          // b-rotl, c-add
		rng->y_state = yp - xp;                    // d-sub
		rng->z_state = yp + wp;                    // e-add
		rng->z_state = rotl(rng->z_state, 19);     // f-rotl
		return xp;
	}

	inline uint32_t multi_pcg32_random_r(
					pcg32_random_t* rng_0, pcg32_random_t* rng_1, pcg32_random_t* rng_2, pcg32_random_t* rng_3) noexcept
	{
		return (pcg32_random_r(rng_0) ^ pcg32_random_r(rng_1)) + (pcg32_random_r(rng_2) ^ pcg32_random_r(rng_3));
	}

	inline uint32_t mutli_romu_quad_random_r(romu64_quad_random_t* rng_0, romu64_quad_random_t* rng_1) noexcept
	{
		return romu_quad_random_r(rng_0) + romu_quad_random_r(rng_1);
	}
} // namespace pcg

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
		fail_salt_too_short,
		fail_master_password_too_short,
		fail_no_suitable_password_encoder,
		fail_could_not_init_hasher,
		fail_no_alphabet
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

	const std::string_view url_safe_symbols = "-_";

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

		const size_t hash_me_size     = (salt.size() + login.size() + master_password.size() + 2 + 2 + 64) * 2;
		const size_t reserve_hash     = hash_me_size + max_password_size + tmp_buffer_size;
		const size_t reserve_password = 2 * max_password_size;

		output.password.reserve(std::max(reserve_hash, reserve_password));

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

		// hash the combined string
		size_t digest_length = crypto_generichash_KEYBYTES_MAX; // should be >= 64

		// build the program and personalize the key if you'd like
		using namespace std::literals;
		std::string_view key = "edit_me!"sv;
		crypto_generichash((uint8_t*)output.password.data() + output.password.size(), digest_length,
						(const unsigned char*)output.password.data(), output.password.size(),
						(const unsigned char*)key.data(), key.size());

		// Make the hash our new string
		output.password.assign(output.password.data() + end_size, digest_length);

		// 512 bit romu pcg
		pcg::romu64_quad_random_t rrng_0 = {0};
		pcg::romu64_quad_random_t rrng_1 = {0};

		// initalize romu with 512 bit hash
		std::memcpy(&rrng_0, output.password.data(), sizeof(pcg::romu64_quad_random_t));
		std::memcpy(&rrng_1, output.password.data() + sizeof(pcg::romu64_quad_random_t),
						sizeof(pcg::romu64_quad_random_t));

		// Use various base encodings to generate the resulting password

		// must be at least 256 to potentially fit entire alphabet
		// (worst-case) (8192-256)/8192 -> 96.8%~ accept rate
		//              (4096-256)/4096 -> 93.7%~ accept rate

		// (nice-case) (512-94)/512 -> 91.7%~ accept rate
		std::array<char, 256> encode_alphabet = {};
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

		// no alphabet
		if (idx == 0) {
			output.result = generate_password_result::fail_no_alphabet;
			return;
		}

		const uint64_t alphabet_size = idx;
		const uint32_t clzeros       = std::countl_zero(alphabet_size);

		const uint32_t mx_shift = clzeros;
		const uint32_t mn_shift = clzeros + 1;

		const uint32_t mx_bits_shift = 64 - mx_shift;
		const uint32_t mn_bits_shift = 64 - mn_shift;

		uint64_t tmp_buf      = 0;
		uint32_t tmp_buf_bits = 0;
		size_t   i            = 0;

		size_t check_i = 0;
		size_t out_i   = 0;

		uint32_t since_lowercase = uint32_t{0xffffffff};
		uint32_t since_uppercase = uint32_t{0xffffffff};
		uint32_t since_digit     = uint32_t{0xffffffff};
		uint32_t since_symbol    = uint32_t{0xffffffff};

		uint32_t circle_buf_size = max_password_size + 8;

		// uint32_t divisor = ((-alphabet_size) / alphabet_size) + 1;
		uint32_t divisor = uint32_t{0xffffffff} / alphabet_size;

		for (;;) {
			uint32_t v = {};

			crypto_stream_xchacha20((unsigned char*)&v, sizeof(v), (const unsigned char*)&rrng_0,
							(const unsigned char*)&rrng_1);
			// rrng_0.y_state += 1;
			rrng_0.x_state += 1;
			// use last 16 bytes of rrng_0 to drive pcg (last 8 aren't used by chacha)
			pcg32_random_r((pcg::pcg32_random_t*)&(rrng_0.y_state));
			// we're now using all 512 bits, 256 are a key and 192 are a nonce

			// do base_x encoding mapping binary data stream into valid character sets
			uint32_t h_value                                                      = v / divisor;
			output.password.data()[max_password_size + (out_i % circle_buf_size)] = encode_alphabet[h_value];
			// discard out of bounds
			out_i += (h_value < alphabet_size);

			for (; check_i < out_i; check_i++) {
				monotonic_increment(since_lowercase);
				monotonic_increment(since_uppercase);
				monotonic_increment(since_digit);
				monotonic_increment(since_symbol);

				// categorize the password character into exclusive groups
				std::string_view potential_password_char = std::string_view{
								output.password.data() + max_password_size + (check_i % circle_buf_size),
								1}; // current_password.substr(idx, 1);
				uint32_t char_flags = classify_password(potential_password_char);

				// reset the counts if any of the flags are set
				since_lowercase = (char_flags & (uint32_t)generate_password_flags::use_lowercase) ? 0 : since_lowercase;
				since_uppercase = (char_flags & (uint32_t)generate_password_flags::use_uppercase) ? 0 : since_uppercase;
				since_digit     = (char_flags & (uint32_t)generate_password_flags::use_digits) ? 0 : since_digit;
				since_symbol    = (char_flags & (uint32_t)generate_password_flags::use_symbols) ? 0 : since_symbol;

				// combine counts back into an aggregated bitset
				uint32_t aggregate_flags =
								((since_lowercase < max_password_size) *
												(uint32_t)generate_password_flags::use_lowercase) |
								((since_uppercase < max_password_size) *
												(uint32_t)generate_password_flags::use_uppercase) |
								((since_digit < max_password_size) * (uint32_t)generate_password_flags::use_digits) |
								((since_symbol < max_password_size) * (uint32_t)generate_password_flags::use_symbols);

				// check if the bitset is satisfied and that we're at least max_length characters
				if ((aggregate_flags & options.flags) == options.flags && !(check_i < max_password_size)) {
					output.result = generate_password_result::ok;
					// copy the ring buffered password back
					for (size_t out_c = 0; out_c < max_password_size; out_c++) {
						output.password.data()[out_c] = output.password.data()[max_password_size +
																			   ((check_i - max_password_size + out_c) %
																							   circle_buf_size)];
					}
					// make into a proper string
					output.password.assign(output.password.data(), max_password_size);
					return;
				}
			}

			// fail if we've run too long
			if (out_i > 0xffff) {
				break;
			}
		}

		output.password.clear();
		return;
	}
} // namespace password_generator