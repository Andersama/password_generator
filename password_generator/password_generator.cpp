// password_generator.cpp : Defines the entry point for the application.
//

#include "password_generator.h"
#include "clip/clip.h"
#include <charconv>
#include <filesystem>

void usage()
{
	std::cout << "usage: <salt> <login> <master_password> [options default: 0 --use-lowercase --use-uppercase "
				 "--use-digits --use-symbols]\n"
				 "\t<unsigned integer>     : set seed, use this to generate different passwords\n"
				 "\t--use-lowercase    -l  : allows and requires at least one character [a-z]\n"
				 "\t--use-uppercase    -u  : allows and requires at least one character [A-Z]\n"
				 "\t--use-digits       -d  : allows and requires at least one character [0-9]\n"
				 "\t--use-symbols      -s  : allows and requires at least one character "
				 "[!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~]\n";
}

int main(int argc, char** argv)
{
	using namespace std::literals;
	password_generator::password_output           out = {};
	password_generator::generate_password_options opt = {};

	opt.flags = ((uint32_t)password_generator::generate_password_flags::use_lowercase) |
				((uint32_t)password_generator::generate_password_flags::use_uppercase) |
				((uint32_t)password_generator::generate_password_flags::use_digits) |
				((uint32_t)password_generator::generate_password_flags::use_symbols);

	if (sodium_init() < 0) {
		out.result = password_generator::generate_password_result::fail_could_not_init_hasher;
		return (int)out.result;
	}

	if (argc >= 4) {
		std::string_view salt  = argv[1];
		std::string_view login = argv[2];
		std::string_view pass  = argv[3];

		uint32_t new_flags = {0};
		bool     seeded    = false;
		size_t   seed      = {0};

		for (size_t i = 4; i < argc; i++) {
			std::string_view arg = argv[i];

			if (arg.compare("--use-lowercase"sv) == 0 || arg.compare("-l"sv) == 0) {
				new_flags |= (uint32_t)password_generator::generate_password_flags::use_lowercase;
			} else if (arg.compare("--use-uppercase"sv) == 0 || arg.compare("-u"sv) == 0) {
				new_flags |= (uint32_t)password_generator::generate_password_flags::use_uppercase;
			} else if (arg.compare("--use-digits"sv) == 0 || arg.compare("-d"sv) == 0) {
				new_flags |= (uint32_t)password_generator::generate_password_flags::use_digits;
			} else if (arg.compare("--use-symbols"sv) == 0 || arg.compare("-s"sv) == 0) {
				new_flags |= (uint32_t)password_generator::generate_password_flags::use_symbols;
			} else if (arg.compare("--max-length"sv) == 0 && ((i + 1) < argc)) {
				std::string_view len = argv[i + 1];
				std::from_chars(len.data(), len.data() + len.size(), opt.max_length);
				i++;
			} else if (arg.compare("--min-length"sv) == 0 && ((i + 1) < argc)) {
				std::string_view len = argv[i + 1];
				std::from_chars(len.data(), len.data() + len.size(), opt.min_length);
				i++;
			} else {
				// try to parse a number as a seed
				seeded = true;
				std::from_chars(arg.data(), arg.data() + arg.size(), seed);
			}
		}

		opt.flags = (new_flags != uint32_t{0}) ? new_flags : opt.flags;
		opt.seed  = (seeded) ? seed : opt.seed;

		generate_password(out, salt, login, pass, opt);

		if (out.result == password_generator::generate_password_result::ok) {
			clip::set_text(out.password);
			std::cout << "password copied to clipboard!\n";
		} else {
			std::cout << "failed to generate password!\n";
			std::cout << "code: " << (int)out.result << '\n';
			std::cout << (((int)out.result < password_generator::result_string.size())
														 ? password_generator::result_string[(int)out.result]
														 : std::string_view{""})
					  << '\n';
		}
	} else {
		usage();
	}

	return (int)out.result;
}
