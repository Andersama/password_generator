// password_generator.cpp : Defines the entry point for the application.
//

#include "password_generator.h"

void usage()
{
	std::cout << "usage: <salt> <login> <master_password> <seed=0> [options default: --use-lowercase --use-uppercase "
				 "--use-digits --use-symbols]\n"
				 "\t--use-lowercase : allows and requires at least one character [a-z]\n"
				 "\t--use-uppercase : allows and requires at least one character [A-Z]\n"
				 "\t--use-digits    : allows and requires at least one character [0-9]\n"
				 "\t--use-symbols   : allows and requires at least one character "
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

	// reserve 8kb
	out.password.reserve(8096);

	if (argc >= 4) {
		// std::string_view program = argv[0];
		std::string_view salt  = argv[1];
		std::string_view login = argv[2];
		std::string_view pass  = argv[3];

		uint32_t new_flags = {0};
		for (size_t i = 4; i < argc; i++) {
			std::string_view opt = argv[i];

			if (opt.compare("--use-lowercase"sv) == 0) {
				new_flags |= (uint32_t)password_generator::generate_password_flags::use_lowercase;
			} else if (opt.compare("--use-uppercase"sv) == 0) {
				new_flags |= (uint32_t)password_generator::generate_password_flags::use_uppercase;
			} else if (opt.compare("--use-digits"sv) == 0) {
				new_flags |= (uint32_t)password_generator::generate_password_flags::use_digits;
			} else if (opt.compare("--use-symbols"sv) == 0) {
				new_flags |= (uint32_t)password_generator::generate_password_flags::use_symbols;
			}
		}

		opt.flags = (new_flags != uint32_t{0}) ? new_flags : opt.flags;

		generate_password(out, salt, login, pass, opt);
	} else {
		usage();
	}

	return (int)out.result;
}
