// password_generator.cpp : Defines the entry point for the application.
//

#include "password_generator.h"
#include "clip/clip.h"
#include <charconv>
#include <filesystem>

#ifdef WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#endif

#undef min
#undef max

// set clipboard text
bool set_text(std::string_view value)
{
	clip::lock l;
	if (l.locked()) {
		l.clear();
		return l.set_data(clip::text_format(), value.data(), value.size());
	} else
		return false;
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

void usage()
{
	std::cout << "usage: \n"
				 "\t--generate         -g  : <salt> <login> <master_password> [options default: 0 --use-lowercase "
				 "--use-uppercase --use-digits --use-symbols]\n"
				 "\t--random           -r  : generates a random password      [options default: 0 --use-lowercase "
				 "--use-uppercase --use-digits --use-symbols]\n"
				 "\t<unsigned integer>     : set seed, use this to generate different passwords\n"
				 "\t--use-lowercase    -l  : allows and requires at least one character [a-z]\n"
				 "\t--use-uppercase    -u  : allows and requires at least one character [A-Z]\n"
				 "\t--use-digits       -d  : allows and requires at least one character [0-9]\n"
				 "\t--use-symbols      -s  : allows and requires at least one character "
				 "[!\"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~]\n"
				 "\t--help             -h  : shows usage\n";
}

int main(int argc, char** argv)
{
	using namespace std::literals;
	password_generator::clearing_resource         clearing_mem;
	password_generator::password_output           out{&clearing_mem};
	password_generator::generate_password_options opt = {};

	opt.flags = ((uint32_t)password_generator::generate_password_flags::use_lowercase) |
				((uint32_t)password_generator::generate_password_flags::use_uppercase) |
				((uint32_t)password_generator::generate_password_flags::use_digits) |
				((uint32_t)password_generator::generate_password_flags::use_symbols);

	if (sodium_init() < 0) {
		out.result = password_generator::generate_password_result::fail_could_not_init_hasher;

		std::cout << "code: " << (int)out.result << '\n';
		std::cout << (((int)out.result < password_generator::result_string.size())
													 ? password_generator::result_string[(int)out.result]
													 : std::string_view{""})
				  << '\n';
		return (int)out.result;
	}

	if (argc <= 1) {
		usage();
	}

	password_generator::clear_string input{&clearing_mem};
	input.reserve(1024);
	password_generator::clear_string buf{&clearing_mem};
	buf.reserve(3 * 1024);

	set_std_echo(false);

	uint32_t new_flags = {0};
	uint64_t seed      = {0};

	bool seeded = false;

	bool opt_lowercase = false;
	bool opt_uppercase = false;
	bool opt_digits    = false;
	bool opt_symbols   = false;

	bool opt_max_length = false;
	bool opt_min_length = false;

	bool opt_random   = false;
	bool opt_password = false;

	bool opt_silent = false;

	std::string_view salt;
	std::string_view login;
	std::string_view pass;

	for (size_t i = 1; i < argc; i++) {
		std::string_view arg = argv[i];

		if (arg.compare("--use-lowercase"sv) == 0 || arg.compare("-l"sv) == 0) {
			new_flags |= (uint32_t)password_generator::generate_password_flags::use_lowercase;
			opt_lowercase = true;
		} else if (arg.compare("--use-uppercase"sv) == 0 || arg.compare("-u"sv) == 0) {
			new_flags |= (uint32_t)password_generator::generate_password_flags::use_uppercase;
			opt_uppercase = true;
		} else if (arg.compare("--use-digits"sv) == 0 || arg.compare("-d"sv) == 0) {
			new_flags |= (uint32_t)password_generator::generate_password_flags::use_digits;
			opt_digits = true;
		} else if (arg.compare("--use-symbols"sv) == 0 || arg.compare("-s"sv) == 0) {
			new_flags |= (uint32_t)password_generator::generate_password_flags::use_symbols;
			opt_symbols = true;
		} else if (arg.compare("--max-length"sv) == 0 && ((i + 1) < argc)) {
			std::string_view len = argv[i + 1];
			std::from_chars(len.data(), len.data() + len.size(), opt.max_length);
			i++;
			opt_max_length = true;
		} else if (arg.compare("--min-length"sv) == 0 && ((i + 1) < argc)) {
			std::string_view len = argv[i + 1];
			std::from_chars(len.data(), len.data() + len.size(), opt.min_length);
			i++;
			opt_min_length = true;
		} else if (arg.compare("-h"sv) == 0 || arg.compare("--help"sv) == 0) {
			usage();
			return (int)out.result;
		} else if (arg.compare("--random"sv) == 0 || arg.compare("-r"sv) == 0) {
			opt_random = true;
		} else if ((arg.compare("--generate"sv) == 0 || arg.compare("-g"sv) == 0) && ((i + 3) < argc)) {
			opt_password = true;
			salt         = argv[i + 1];
			login        = argv[i + 2];
			pass         = argv[i + 3];
		} else if (arg.compare("--silent"sv) == 0 || arg.compare("-s"sv) == 0) {
			opt_silent = true;
		} else {
			// try to parse a number as a seed
			seeded = true;
			std::from_chars(arg.data(), arg.data() + arg.size(), seed);
		}
	}

	// we can enter a string of y's and n's if we want here
	char do_random = 0;

	if (!opt_random) {
		std::cout << "\nrandom?    : [y/n] ";
		do {
			std::cin >> do_random;
			if (do_random == 'y' || do_random == 'Y' || do_random == 'n' || do_random == 'N') {
				break;
			} else {
				std::cout << "\rrandom?    : [y/n] (enter [yYnN]) ";
			}
		} while (true);
		opt_random = (do_random == 'y' || do_random == 'Y');
	}

	char use_lowercase = 0;
	if (!opt_lowercase) {
		std::cout << "\nlowercase? : [y/n] ";
		do {
			std::cin >> use_lowercase;
			if (use_lowercase == 'y' || use_lowercase == 'Y' || use_lowercase == 'n' || use_lowercase == 'N') {
				break;
			} else {
				std::cout << "\rlowercase? : [y/n] (enter [yYnN]) ";
			}
		} while (true);
		new_flags |= (uint32_t)password_generator::generate_password_flags::use_lowercase *
					 (use_lowercase == 'y' || use_lowercase == 'Y');
	}

	char use_uppercase = 0;
	if (!opt_uppercase) {
		std::cout << "\nuppercase? : [y/n] ";
		do {
			std::cin >> use_uppercase;
			if (use_uppercase == 'y' || use_uppercase == 'Y' || use_uppercase == 'n' || use_uppercase == 'N') {
				break;
			} else {
				std::cout << "\ruppercase? : [y/n] (enter [yYnN]) ";
			}
		} while (true);
		new_flags |= (uint32_t)password_generator::generate_password_flags::use_uppercase *
					 (use_uppercase == 'y' || use_uppercase == 'Y');
	}

	char use_digits = 0;
	if (!opt_digits) {
		std::cout << "\ndigits?    : [y/n] ";
		do {
			std::cin >> use_digits;
			if (use_digits == 'y' || use_digits == 'Y' || use_digits == 'n' || use_digits == 'N') {
				break;
			} else {
				std::cout << "\rdigits?    : [y/n] (enter [yYnN]) ";
			}
		} while (true);
		new_flags |= (uint32_t)password_generator::generate_password_flags::use_digits *
					 (use_digits == 'y' || use_digits == 'Y');
	}

	char use_symbols = 0;
	if (!opt_symbols) {
		std::cout << "\nsymbols?   : [y/n] ";
		do {
			std::cin >> use_symbols;
			if (use_symbols == 'y' || use_symbols == 'Y' || use_symbols == 'n' || use_symbols == 'N') {
				break;
			} else {
				std::cout << "\rsymbols?   : [y/n] (enter [yYnN]) ";
			}
		} while (true);
		new_flags |= (uint32_t)password_generator::generate_password_flags::use_symbols *
					 (use_symbols == 'y' || use_symbols == 'Y');
	}

	bool cin_ok = false;
	if (!opt_max_length) {
		std::cout << "\nmax_length?: <unsigned integer> ";
		size_t max_length = {32};
		do {
			cin_ok = (bool)(std::cin >> max_length);
			if (cin_ok && max_length < 65535) {
				break;
			} else {
				std::cout << "\rmax_length?: <unsigned integer> (enter a valid number under 65535) ";
				std::cin.clear();
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			}
		} while (true);
		opt.max_length = max_length;
	}

	if (opt_random || do_random == 'y' || do_random == 'Y') {
		opt.flags = (new_flags != uint32_t{0}) ? new_flags : opt.flags;

		generate_random_password(out, opt);

		if (out.result == password_generator::generate_password_result::ok) {
			set_text(std::string_view{out.password.data(), out.password.size()});
			std::cout << "password copied to clipboard!\n";
		} else {
			std::cout << "failed to generate password!\n";
			std::cout << "code: " << (int)out.result << '\n';
			std::cout << (((int)out.result < password_generator::result_string.size())
														 ? password_generator::result_string[(int)out.result]
														 : std::string_view{""})
					  << '\n';
		}

		return (int)out.result;
	}

	size_t salt_size = {};
	if (!opt_password) {
		std::cout << "\nsalt       : ";
		std::getline(std::cin, input);
		buf.append(input.data(), input.size());

		salt_size = input.size();
	}

	size_t login_size = {};
	if (!opt_password) {
		std::cout << "\nlogin      : ";
		std::getline(std::cin, input);
		buf.append(input.data(), input.size());
		login_size = input.size();
	}

	size_t password_size = {};
	if (!opt_password) {
		std::cout << "\npassword   : [must be at least 8 characters] ";
		do {
			std::getline(std::cin, input);
			if (input.size() >= 8) {
				break;
			} else {
				std::cout << "\rpassword   : [must be at least 8 characters] (enter a valid password) ";
			}
		} while (true);

		buf.append(input.data(), input.size());
		password_size = input.size();
	}

	if (!opt_password) {
		salt  = std::string_view{buf.data(), salt_size};
		login = std::string_view{buf.data() + salt_size, login_size};
		pass  = std::string_view{buf.data() + salt_size + login_size, password_size};
	}

	if (!seeded) {
		std::cout << "\nseed?      : <unsigned integer> ";
		do {
			cin_ok = (bool)(std::cin >> seed);
			if (cin_ok) {
				break;
			} else {
				std::cout << "\rseed?      : <unsigned integer> (enter a valid number) ";
				std::cin.clear();
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			}
		} while (true);
	}
	opt.seed = seed;

	opt.flags = (new_flags != uint32_t{0}) ? new_flags : opt.flags;

	generate_password(out, salt, login, pass, opt);

	std::cout << '\n';

	if (out.result == password_generator::generate_password_result::ok) {
		set_text(std::string_view{out.password.data(), out.password.size()});
		std::cout << "password copied to clipboard!\n";
	} else {
		std::cout << "failed to generate password!\n";
		std::cout << "code: " << (int)out.result << '\n';
		std::cout << (((int)out.result < password_generator::result_string.size())
													 ? password_generator::result_string[(int)out.result]
													 : std::string_view{""})
				  << '\n';
	}

	return (int)out.result;
}
