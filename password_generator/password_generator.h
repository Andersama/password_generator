#pragma once
// password_generator.h : Include file for standard system include files,
// or project specific include files.

#include <iostream>
#include <string>
#include <string_view>
#include <charconv>
#include <array>
#include <algorithm>

#include <memory>
#include <memory_resource>

#include <sodium.h>

namespace rng {
	inline uint64_t rotl(uint64_t d, uint64_t lrot) noexcept
	{
		return ((d << (lrot)) | (d >> (8 * sizeof(d) - (lrot))));
	}

	inline uint64_t self_rotl_high(uint64_t val) noexcept
	{
		return rotl(val, val >> (64 - 3));
	}

	inline uint64_t self_rotl_low(uint64_t val) noexcept
	{
		return rotl(val, val & 0x7);
	}
} // namespace rng

namespace password_generator {

	class clearing_resource : public std::pmr::memory_resource {
private:
		struct allocation_record {
			void*  ptr       = {};
			size_t size      = {};
			size_t alignment = {};
		};

public:
		explicit clearing_resource(std::pmr::memory_resource* upstream = std::pmr::get_default_resource())
			: upstream_resource(upstream)
		{
		}

		void* do_allocate(size_t bytes, size_t alignment) override
		{
			void* mem = upstream_resource->allocate(bytes, alignment);
			std::memset(mem, 0, bytes);
			previous.emplace_back(mem, bytes, alignment);
			return mem;
		}

		void do_deallocate(void* ptr, size_t bytes, size_t alignment) override
		{
			auto it = std::find_if(previous.begin(), previous.end(),
							[&ptr, &bytes](const allocation_record& record) { return record.ptr == ptr; });
			if (it != previous.end()) {
				std::memset(ptr, 0, it->size);
				upstream_resource->deallocate(ptr, it->size, it->alignment);
				previous.erase(it);
			}
		}

		bool do_is_equal(const std::pmr::memory_resource& other) const noexcept override
		{
			return this == &other;
		}

private:
		std::vector<allocation_record> previous;
		std::pmr::memory_resource*     upstream_resource;
	};

	struct clear_string : std::pmr::string {
		clear_string(std::pmr::memory_resource* upstream = std::pmr::get_default_resource())
			: std::pmr::string(upstream)
		{
		}

		constexpr void clear() noexcept
		{
			size_t cap = capacity();
			char*  dat = data();
			for (size_t x = 0; x < cap; x++) {
				dat[x] = 0;
			}
			std::pmr::string::clear();
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

		// custom rules
	};

	enum class generate_password_result {
		ok   = 0,
		fail = 1,
		fail_salt_too_short,
		fail_master_password_too_short,
		fail_no_suitable_password_encoder,
		fail_could_not_init_hasher,
		fail_no_alphabet,
		fail_min_max_lengths,
		fail_too_large_max_length,
		fail_password_required_n_chars
	};

	using namespace std::literals;
	std::array<std::string_view, ((uint32_t)generate_password_result::fail_password_required_n_chars) + 1>
					result_string = {"ok"sv, "could not find a suitable password to meet the requirements"sv,
									"salt too short"sv, "password too short"sv, "no suitable password encoder"sv,
									"coult not initialize hasher"sv, "no alphabet selected"sv,
									"min length not <= than max length"sv,
									"max length was too large keep under 65535"sv,
									"max length was under n required characters needed to complete password"sv};

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

		password_output(std::pmr::memory_resource* upstream = std::pmr::get_default_resource()) : password(upstream)
		{
		}
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
		T next = value + 1;
		value  = (value < next) ? next : value;
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

		const size_t max_password_size = options.max_length;
		if (options.min_length > options.max_length) {
			output.result = generate_password_result::fail_min_max_lengths;
			return;
		}

		// this limit is so we don't explode our allocators
		if (options.max_length > 0xffff) {
			output.result = generate_password_result::fail_too_large_max_length;
			return;
		}
		// Use various base encodings to generate the resulting password

		// must be at least 256 to potentially fit entire alphabet
		// (worst-case) (8192-256)/8192 -> 96.8%~ accept rate
		//              (4096-256)/4096 -> 93.7%~ accept rate

		// (nice-case) (512-94)/512 -> 91.7%~ accept rate
		std::array<char, 256> encode_alphabet = {};
		uint32_t              idx             = 0;

		uint32_t required_chars = 0;

		if (options.flags & (uint32_t)generate_password_flags::use_lowercase) {
			required_chars += 1;
			for (size_t c = 0; c < lowercase.size(); c++) {
				encode_alphabet[idx++] = lowercase[c];
			}
		}

		if (options.flags & (uint32_t)generate_password_flags::use_uppercase) {
			required_chars += 1;
			for (size_t c = 0; c < uppercase.size(); c++) {
				encode_alphabet[idx++] = uppercase[c];
			}
		}

		if (options.flags & (uint32_t)generate_password_flags::use_digits) {
			required_chars += 1;
			for (size_t c = 0; c < digits.size(); c++) {
				encode_alphabet[idx++] = digits[c];
			}
		}

		if (options.flags & (uint32_t)generate_password_flags::use_symbols) {
			required_chars += 1;
			for (size_t c = 0; c < symbols.size(); c++) {
				encode_alphabet[idx++] = symbols[c];
			}
		}

		if (options.max_length < required_chars) {
			output.result = generate_password_result::fail_password_required_n_chars;
			return;
		}

		// no alphabet
		if (idx == 0) {
			output.result = generate_password_result::fail_no_alphabet;
			return;
		}

		const size_t tmp_buffer_size  = 8096;
		const size_t hash_me_size     = (salt.size() + login.size() + master_password.size() + 2 + 2 + 64) * 2;
		const size_t reserve_hash     = hash_me_size + max_password_size + tmp_buffer_size;
		const size_t reserve_password = 2 * max_password_size;

		// build our string
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

		// store the hash
		std::array<uint64_t, (crypto_generichash_KEYBYTES_MAX / 8) + 1> hashed = {};
		std::memcpy(hashed.data(), output.password.data() + end_size, digest_length);

		// obliterate the buffer
		std::memset(output.password.data(), 0, output.password.capacity());

		const uint64_t alphabet_size = idx;

		size_t check_i = 0;
		size_t out_i   = 0;

		uint32_t since_lowercase = uint32_t{0xffffffff};
		uint32_t since_uppercase = uint32_t{0xffffffff};
		uint32_t since_digit     = uint32_t{0xffffffff};
		uint32_t since_symbol    = uint32_t{0xffffffff};

		uint32_t circle_buf_size = max_password_size + 8;

		uint32_t divisor = uint32_t{0xffffffff} / alphabet_size;

		for (;;) {
			uint32_t v = {};

			crypto_stream_xchacha20((unsigned char*)&v, sizeof(v), ((const unsigned char*)hashed.data()),
							((const unsigned char*)hashed.data()) +
											crypto_stream_xchacha20_KEYBYTES); // crypto_stream_xchacha20_NONCEBYTES
			hashed[1] += 1;

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
					std::memset(hashed.data(), 0, hashed.size());

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

		std::memset(hashed.data(), 0, hashed.size());
		output.password.clear();
		return;
	}

	void random_data(char* data, size_t length)
	{
		std::array<uint64_t, (crypto_generichash_KEYBYTES_MAX / sizeof(uint64_t))* 2 + 1> temp   = {};
		std::array<uint64_t, 3>                                                           temp_2 = {};
		std::string_view                                                                  key    = "edit_me!"sv;

		temp_2[1] = (size_t)data;
		temp_2[2] = length;

		size_t l = 0;
		do {
			randombytes_buf(temp.data(), temp.size() * sizeof(uint64_t));
			// make sure randombytes_buf is not our only source of randomness
			std::chrono::steady_clock::time_point n = std::chrono::steady_clock::now();
			temp_2[0]                               = n.time_since_epoch().count();
			temp_2[2] += 1;

			size_t digest_length = crypto_generichash_KEYBYTES_MAX;

			using namespace std::literals;

			crypto_generichash((uint8_t*)temp.data(), digest_length, (const unsigned char*)temp_2.data(), temp_2.size(),
							(const unsigned char*)key.data(), key.size());

			size_t i = 0;
			for (; i < digest_length && l < length; i++, l++) {
				data[l] = ((char*)temp.data())[i] ^ ((char*)temp.data())[i + digest_length];
			}
		} while (l < length);
	}

	void generate_random_password(password_output& output, const generate_password_options& options)
	{
		output.result                         = generate_password_result::fail;
		std::array<char, 256> encode_alphabet = {};

		std::array<uint32_t, 8> temp = {};

		const size_t max_password_size = options.max_length;
		const size_t circle_buf_size   = max_password_size + temp.size() + 8;
		output.password.reserve(circle_buf_size * 2);

		uint32_t idx            = 0;
		uint32_t required_chars = 0;

		if (options.flags & (uint32_t)generate_password_flags::use_lowercase) {
			required_chars += 1;
			for (size_t c = 0; c < lowercase.size(); c++) {
				encode_alphabet[idx++] = lowercase[c];
			}
		}

		if (options.flags & (uint32_t)generate_password_flags::use_uppercase) {
			required_chars += 1;
			for (size_t c = 0; c < uppercase.size(); c++) {
				encode_alphabet[idx++] = uppercase[c];
			}
		}

		if (options.flags & (uint32_t)generate_password_flags::use_digits) {
			required_chars += 1;
			for (size_t c = 0; c < digits.size(); c++) {
				encode_alphabet[idx++] = digits[c];
			}
		}

		if (options.flags & (uint32_t)generate_password_flags::use_symbols) {
			required_chars += 1;
			for (size_t c = 0; c < symbols.size(); c++) {
				encode_alphabet[idx++] = symbols[c];
			}
		}

		// really make sure our data's shuffled around, permute our output
		for (size_t x = 1; x < idx; x++) {
			size_t range   = x;

			size_t divisor = (~size_t{0}) / range;
			size_t rng     = {};
			random_data((char*)&rng, sizeof(rng));
			size_t v = rng / divisor;
			if (range) {
				while (v >= range) {
					random_data((char*)&rng, sizeof(rng));
					v = rng / divisor;
				}
			}

			std::swap(encode_alphabet[x], encode_alphabet[v]);
		}

		const uint32_t alphabet_size = idx;

		size_t check_i = 0;
		size_t out_i   = 0;

		uint32_t since_lowercase = uint32_t{0xffffffff};
		uint32_t since_uppercase = uint32_t{0xffffffff};
		uint32_t since_digit     = uint32_t{0xffffffff};
		uint32_t since_symbol    = uint32_t{0xffffffff};

		uint32_t divisor = uint32_t{0xffffffff} / alphabet_size;

		for (;;) {
			random_data((char*)temp.data(), temp.size() * sizeof(uint32_t));

			for (size_t i = 0; i < temp.size(); i++) {
				// do base_x encoding mapping binary data stream into valid character sets
				uint32_t h_value                                                      = temp[i] / divisor;
				output.password.data()[max_password_size + (out_i % circle_buf_size)] = encode_alphabet[h_value];
				// discard out of bounds
				out_i += (h_value < alphabet_size);
			}

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
					std::memset(temp.data(), 0, temp.size());

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
		}

		std::memset(temp.data(), 0, temp.size());
		return;
	}
} // namespace password_generator