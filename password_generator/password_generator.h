#pragma once
// password_generator.h : Include file for standard system include files,
// or project specific include files.

#include <iostream>
#include <vector>
#include <string>
#include <string_view>
#include <charconv>
#include <array>
#include <algorithm>

#include <memory>
#include <memory_resource>
#include <span>

#include <fstream>
#include <filesystem>

#include <sodium.h>

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#undef min
#undef max

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

			constexpr allocation_record(void* ptr, size_t size, size_t alignment)
				: ptr(ptr), size(size), alignment(alignment){};
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

	// I only came up with 4 main categories I'd typically use, expand this if you'd like
	using flag_type = uint32_t;
	// to customize: add a new enum value here (must be power of 2, so do 1 << #)
	enum class generate_password_flags : flag_type {
		use_lowercase = 1 << 0,
		use_uppercase = 1 << 1,
		use_digits    = 1 << 2,
		use_symbols   = 1 << 3
		// custom rules
	};

	enum class generate_password_result : flag_type {
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

		flag_type flags = ((flag_type)generate_password_flags::use_lowercase |
						   (flag_type)generate_password_flags::use_uppercase |
						   (flag_type)generate_password_flags::use_digits |
						   (flag_type)generate_password_flags::use_symbols);
	};

	// to customize : add a string view which the enum value will capture
	const std::string_view lowercase = "abcdefghijklmnopqrstuvwxyz";
	const std::string_view uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	const std::string_view digits    = "0123456789";
	const std::string_view symbols   = "!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~";

	// for example:
	const std::string_view limited_symbols = "@&#$!?";
	// or maybe:
	const std::string_view url_safe_symbols = "-_";

	struct password_output {
		generate_password_result result = generate_password_result::ok;
		clear_string             password;

		password_output(std::pmr::memory_resource* upstream = std::pmr::get_default_resource()) : password(upstream)
		{
		}
	};

	// iterate over the string view and mark each character with it's enum value using |=
	// could be made conditionless*
	inline void generate_masks(flag_type flags, std::array<flag_type, 256>& masks)
	{
		if (flags & (flag_type)generate_password_flags::use_lowercase) {
			for (size_t c = 0; c < lowercase.size(); c++) {
				masks[(uint8_t)lowercase[c]] |= (flag_type)generate_password_flags::use_lowercase;
			}
		}

		if (flags & (flag_type)generate_password_flags::use_uppercase) {
			for (size_t c = 0; c < uppercase.size(); c++) {
				masks[(uint8_t)uppercase[c]] |= (flag_type)generate_password_flags::use_uppercase;
			}
		}

		if (flags & (flag_type)generate_password_flags::use_digits) {
			for (size_t c = 0; c < digits.size(); c++) {
				masks[(uint8_t)digits[c]] |= (flag_type)generate_password_flags::use_digits;
			}
		}

		if (flags & (flag_type)generate_password_flags::use_symbols) {
			for (size_t c = 0; c < symbols.size(); c++) {
				masks[(uint8_t)symbols[c]] = (flag_type)generate_password_flags::use_symbols;
			}
		}

		// add up to 32* different categories
	}

	struct alphabet_result {
		uint32_t alphabet_size  = {};
		uint32_t required_chars = {};
	};
	// add alphabets as needed
	inline alphabet_result generate_alphabet(flag_type flags, std::array<char, 256>& alphabet)
	{
		std::array<bool, 256> in_use = {};

		for (size_t i = 0; i < alphabet.size(); i++)
			alphabet[i] = 0;
		for (size_t i = 0; i < in_use.size(); i++)
			in_use[i] = false;

		// to deal with the fact we need consistancy between different flags being set and the alphbet we generate
		// we're going to sort the output alphabet.
		// we're doing an american flag sort over the set of unique characters

		// we need to signal to the outside function how many character classes we're going to need
		// this sets a minimum number of characters required to even make generating a password possible
		// note: this is effectively popcount of flags*
		alphabet_result result = {};

		// to extend add another condition and iterate over the associated string view
		if (flags & (flag_type)generate_password_flags::use_lowercase) {
			result.required_chars += 1;
			for (size_t c = 0; c < lowercase.size(); c++) {
				in_use[(uint8_t)lowercase[c]] = true;
			}
		}

		if (flags & (flag_type)generate_password_flags::use_uppercase) {
			result.required_chars += 1;
			for (size_t c = 0; c < uppercase.size(); c++) {
				in_use[(uint8_t)uppercase[c]] = true;
			}
		}

		if (flags & (flag_type)generate_password_flags::use_digits) {
			result.required_chars += 1;
			for (size_t c = 0; c < digits.size(); c++) {
				in_use[(uint8_t)digits[c]] = true;
			}
		}

		if (flags & (flag_type)generate_password_flags::use_symbols) {
			result.required_chars += 1;
			for (size_t c = 0; c < symbols.size(); c++) {
				in_use[(uint8_t)symbols[c]] = true;
			}
		}

		for (size_t i = 0; i < in_use.size(); i++) {
			alphabet[result.alphabet_size] = (char)i;
			result.alphabet_size += in_use[i];
		}

		return result;
	}

	inline flag_type classify_character(uint8_t c, std::array<flag_type, 256>& masks)
	{
		return masks[c];
	}

	inline flag_type classify_password(std::string_view password, std::array<flag_type, 256>& masks)
	{
		flag_type out_char_flags = {0};
		for (size_t i = 0; i < password.size(); i++) {
			out_char_flags |= masks[(uint8_t)password[i]];
		}
		return out_char_flags;
	}

	template<typename T> inline void monotonic_increment(T& value)
	{
		T next = value + 1;
		value  = (value < next) ? next : value;
	}

	// ripped from stackoverflow
	void set_std_echo(bool enable = true)
	{
#ifdef WIN32
		HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
		DWORD  mode;
		GetConsoleMode(hStdin, &mode);

		if (!enable)
			mode &= ~ENABLE_ECHO_INPUT;
		else
			mode |= ENABLE_ECHO_INPUT;

		SetConsoleMode(hStdin, mode);

#else
		struct termios tty;
		tcgetattr(STDIN_FILENO, &tty);
		if (!enable)
			tty.c_lflag &= ~ECHO;
		else
			tty.c_lflag |= ECHO;

		(void)tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
	}

	bool get_std_echo()
	{
#ifdef WIN32
		HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
		DWORD  mode;
		GetConsoleMode(hStdin, &mode);

		return (mode & ENABLE_ECHO_INPUT);
#else
		struct termios tty;
		tcgetattr(STDIN_FILENO, &tty);

		return tty.c_lflag & ECHO;
#endif
	}

	void generate_password(password_output& output, std::string_view salt, std::string_view login,
					std::string_view master_password, const generate_password_options& options)
	{
		using namespace std::literals;

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

		alphabet_result alphabet_stats = generate_alphabet(options.flags, encode_alphabet);
		uint32_t&       required_chars = alphabet_stats.required_chars;
		uint32_t        idx            = alphabet_stats.alphabet_size;

		if (options.max_length < required_chars) {
			output.result = generate_password_result::fail_password_required_n_chars;
			return;
		}

		// no alphabet
		if (idx == 0) {
			output.result = generate_password_result::fail_no_alphabet;
			return;
		}

		std::array<flag_type, 256> character_categories = {0};
		generate_masks(options.flags, character_categories);

		static_assert(false && "personalize with your own splitter string, remove this assert then build");
		const std::string_view splitter     = "Xf*e!BRP0XzJ/#ep"sv; // edit me
		size_t                 splitter_div = splitter.size() / 2;
		size_t                 splitter_rem = splitter.size() % 2;

		const size_t tmp_buffer_size = 8096;
		const size_t hash_me_size    = (salt.size() + login.size() + master_password.size() + splitter.size() + 64) * 2;
		const size_t reserve_hash    = hash_me_size + max_password_size + tmp_buffer_size;
		const size_t reserve_password = 2 * max_password_size;

		// build our string
		output.password.reserve(std::max(reserve_hash, reserve_password));

		output.password.append(salt.data(), salt.size());
		output.password.append(splitter.data(), splitter_div);
		output.password.append(login.data(), login.size());
		output.password.append(splitter.data() + splitter_div, splitter_div + splitter_rem);
		output.password.append(master_password.data(), master_password.size());

		size_t num_offset     = output.password.size() + 1;
		size_t end_num_offset = output.password.size() + 1 + 32;

		output.password.append("{________________________________}", 34);

		size_t end_size = output.password.size();

		std::to_chars(output.password.data() + num_offset, output.password.data() + end_num_offset, options.seed);

		// hash the combined string
		size_t digest_length = crypto_generichash_KEYBYTES_MAX; // should be >= 64

		static_assert(false && "personalize the hash with your own key, remove this assert then build (change the "
							   "length if you'd like)");
		std::array<uint8_t, 64> key_data = {0x7D, 0x58, 0x2E, 0x26, 0x09, 0x1C, 0x3F, 0x3F, 0x24, 0x40, 0x3F, 0x2F,
						0x5C, 0x5A, 0x0F, 0x10, 0x3F, 0x6D, 0x51, 0x3F, 0x4F, 0x0D, 0x3F, 0x67, 0x3F, 0x46, 0x7A, 0x51,
						0x43, 0x46, 0x3F, 0x3F, 0x0D, 0x5B, 0x7C, 0x23, 0x3F, 0x3F, 0x3F, 0x3F, 0x26, 0x3F, 0x67, 0x3F,
						0x3A, 0x3F, 0x3F, 0x1F, 0x3F, 0x5C, 0x3F, 0x08, 0x19, 0x3F, 0x3F, 0x1F, 0x3F, 0x66, 0x4B, 0x0D,
						0x0A, 0x6A, 0x24, 0x42}; // edit me

		crypto_generichash((uint8_t*)output.password.data() + output.password.size(), digest_length,
						(const unsigned char*)output.password.data(), output.password.size(),
						(const unsigned char*)key_data.data(), key_data.size());

		// store the hash
		std::array<uint64_t, (crypto_generichash_KEYBYTES_MAX / 8) + 1> hashed = {};
		std::memcpy(hashed.data(), output.password.data() + end_size, digest_length);

		// obliterate the buffer
		std::memset(output.password.data(), 0, output.password.capacity());

		const uint64_t alphabet_size = idx;

		size_t check_i = 0;
		size_t out_i   = 0;

		std::array<uint32_t, sizeof(flag_type)* 8> counts = {0};
		for (size_t i = 0; i < counts.size(); i++) {
			counts[i] = ~uint32_t{0};
		}

		// arbitrary selection
		uint32_t& since_lowercase = counts[0];
		uint32_t& since_uppercase = counts[1];
		uint32_t& since_digit     = counts[2];
		uint32_t& since_symbol    = counts[3];

		uint32_t circle_buf_size = max_password_size + 8;

		// uint32_t divisor = uint32_t{0xffffffff} / alphabet_size;

		uint32_t limit   = (~uint32_t{0} - (alphabet_size - 1));
		uint32_t limit_d = limit / alphabet_size;
		uint32_t limit_r = limit % alphabet_size;

		uint32_t bmask = (~uint32_t{0}) >> std::countl_zero((alphabet_size - 1) | 1);

		for (;;) {
			uint32_t v = {};

			crypto_stream_xchacha20((unsigned char*)&v, sizeof(v), ((const unsigned char*)hashed.data()),
							((const unsigned char*)hashed.data()) +
											crypto_stream_xchacha20_KEYBYTES); // crypto_stream_xchacha20_NONCEBYTES
			hashed[1] += 1;

			uint64_t m       = uint64_t{v} * uint64_t{alphabet_size};
			uint32_t h_value = m >> 32;     // high part of m
			uint32_t l_value = uint32_t(m); // low part of m
			// uint32_t h_value = v & bmask;
			//  do base_x encoding mapping binary data stream into valid character sets
			// uint32_t h_value                                                      = v / divisor;
			output.password.data()[max_password_size + (out_i % circle_buf_size)] = encode_alphabet[h_value];
			// discard out of bounds
			out_i += (l_value >= limit_r);
			// out_i += (h_value < alphabet_size);

			for (; check_i < out_i; check_i++) {
				for (size_t i = 0; i < counts.size(); i++) {
					monotonic_increment(counts[i]);
				}

				flag_type char_flags = classify_character(
								output.password.data()[max_password_size + (check_i % circle_buf_size)],
								character_categories);

				// reset the counts if any of the flags are set
				// combine counts back into an aggregated bitset
				flag_type aggregate_flags = {0};
				for (size_t i = 0; i < counts.size(); i++) {
					flag_type mask = (1 << i);
					counts[i]      = (char_flags & mask) ? 0 : counts[i];
					aggregate_flags |= (counts[i] < max_password_size) * mask;
				}

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
		static_assert(false && "personalize the hash with your own key, remove this assert then build (change the "
							   "length if you'd like)");
		std::array<uint8_t, 64> key_data = {0x7D, 0x58, 0x2E, 0x26, 0x09, 0x1C, 0x3F, 0x3F, 0x24, 0x40, 0x3F, 0x2F,
						0x5C, 0x5A, 0x0F, 0x10, 0x3F, 0x6D, 0x51, 0x3F, 0x4F, 0x0D, 0x3F, 0x67, 0x3F, 0x46, 0x7A, 0x51,
						0x43, 0x46, 0x3F, 0x3F, 0x0D, 0x5B, 0x7C, 0x23, 0x3F, 0x3F, 0x3F, 0x3F, 0x26, 0x3F, 0x67, 0x3F,
						0x3A, 0x3F, 0x3F, 0x1F, 0x3F, 0x5C, 0x3F, 0x08, 0x19, 0x3F, 0x3F, 0x1F, 0x3F, 0x66, 0x4B, 0x0D,
						0x0A, 0x6A, 0x24, 0x42}; // edit me

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
							(const unsigned char*)key_data.data(), key_data.size());

			size_t i = 0;
			for (; i < digest_length && l < length; i++, l++) {
				data[l] = ((char*)temp.data())[i] ^ ((char*)temp.data())[i + digest_length];
			}
		} while (l < length);
	}

	// probably way overcomplicated
	void generate_random_password(password_output& output, const generate_password_options& options)
	{
		output.result                         = generate_password_result::fail;
		std::array<char, 256> encode_alphabet = {};

		std::array<uint32_t, 8> temp = {};

		const size_t max_password_size = options.max_length;
		const size_t circle_buf_size   = max_password_size + temp.size() + 8;
		output.password.reserve(circle_buf_size * 2);

		alphabet_result alphabet_stats = generate_alphabet(options.flags, encode_alphabet);
		uint32_t&       required_chars = alphabet_stats.required_chars;
		uint32_t        idx            = alphabet_stats.alphabet_size;

		if (options.max_length < required_chars) {
			output.result = generate_password_result::fail_password_required_n_chars;
			return;
		}

		// no alphabet
		if (idx == 0) {
			output.result = generate_password_result::fail_no_alphabet;
			return;
		}

		// really make sure our data's shuffled around, permute our output
		// here we're banking that whatever weird bias our data stream may
		// have that we'll spread it out
		for (size_t x = 1; x < idx; x++) {
			size_t range = x;

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

		std::array<flag_type, 256> character_categories = {0};
		generate_masks(options.flags, character_categories);

		const uint32_t alphabet_size = idx;

		size_t check_i = 0;
		size_t out_i   = 0;

		std::array<uint32_t, sizeof(flag_type)* 8> counts = {0};
		for (size_t i = 0; i < counts.size(); i++) {
			counts[i] = ~uint32_t{0};
		}

		// arbitrary selection
		uint32_t& since_lowercase = counts[0];
		uint32_t& since_uppercase = counts[1];
		uint32_t& since_digit     = counts[2];
		uint32_t& since_symbol    = counts[3];

		uint32_t divisor = uint32_t{0xffffffff} / alphabet_size;

		uint32_t limit   = (~uint32_t{0} - (alphabet_size - 1));
		uint32_t limit_d = limit / alphabet_size;
		uint32_t limit_r = limit % alphabet_size;

		uint32_t bmask = (~uint32_t{0}) >> std::countl_zero((alphabet_size - 1) | 1);

		for (;;) {
			random_data((char*)temp.data(), temp.size() * sizeof(uint32_t));

			for (size_t i = 0; i < temp.size(); i++) {
				// do base_x encoding mapping binary data stream into valid character sets
				uint64_t m       = uint64_t{temp[i]} * uint64_t{alphabet_size};
				uint32_t h_value = m >> 32;     // high part of m
				uint32_t l_value = uint32_t(m); // low part of m
				// uint32_t h_value = temp[i] & bmask;

				output.password.data()[max_password_size + (out_i % circle_buf_size)] = encode_alphabet[h_value];
				// discard out of bounds
				// out_i += (h_value < alphabet_size);
				out_i += (l_value >= limit_r);
				// out_i += (h_value < alphabet_size);
			}

			for (; check_i < out_i; check_i++) {
				for (size_t i = 0; i < counts.size(); i++) {
					monotonic_increment(counts[i]);
				}
				// categorize the password character into their respective groups
				flag_type char_flags = classify_character(
								output.password.data()[max_password_size + (check_i % circle_buf_size)],
								character_categories);

				flag_type aggregate_flags = {0};
				for (size_t i = 0; i < counts.size(); i++) {
					flag_type mask = (1 << i);
					counts[i]      = (char_flags & mask) ? 0 : counts[i];
					aggregate_flags |= (counts[i] < max_password_size) * mask;
				}

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