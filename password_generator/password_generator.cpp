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
	std::cout << "usage: <salt> <login> <master_password> [options default: 0 --use-lowercase --use-uppercase "
				 "--use-digits --use-symbols]\n"
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

	if (argc >= 4) {
		std::string_view salt  = argv[1];
		std::string_view login = argv[2];
		std::string_view pass  = argv[3];

		uint32_t new_flags  = {0};
		bool     seeded     = false;
		size_t   seed       = {0};
		bool     show_usage = false;

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
			} else if (arg.compare("-h") == 0 || arg.compare("--help") == 0) {
				usage();
				return (int)out.result;
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
	} else {
		usage();
		password_generator::clear_string input{&clearing_mem};
		input.reserve(1024);
		password_generator::clear_string buf{&clearing_mem};
		buf.reserve(3 * 1024);

		set_std_echo(false);

		std::cout << "\nsalt       : ";
		std::getline(std::cin, input);
		buf.append(input.data(), input.size());
		size_t salt_size = input.size();

		std::cout << "\nlogin      : ";
		std::getline(std::cin, input);
		buf.append(input.data(), input.size());
		size_t login_size = input.size();

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
		size_t password_size = input.size();

		std::string_view salt{buf.data(), salt_size};
		std::string_view login{buf.data() + salt_size, login_size};
		std::string_view pass{buf.data() + salt_size + login_size, password_size};

		uint32_t new_flags = {0};

		// we can enter a string of y's and n's if we want here
		char use_lowercase = 0;
		std::cout << "\nlowercase? : [y/n]";
		do {
			std::cin >> use_lowercase;
			if (use_lowercase == 'y' || use_lowercase == 'Y' || use_lowercase == 'n' || use_lowercase == 'N') {
				break;
			} else {
				std::cout << "\rlowercase? : [y/n] (enter [yYnN])";
			}
		} while (true);
		new_flags |= (uint32_t)password_generator::generate_password_flags::use_lowercase *
					 (use_lowercase == 'y' || use_lowercase == 'Y');

		char use_uppercase = 0;
		std::cout << "\nuppercase? : [y/n]";
		do {
			std::cin >> use_uppercase;
			if (use_uppercase == 'y' || use_uppercase == 'Y' || use_uppercase == 'n' || use_uppercase == 'N') {
				break;
			} else {
				std::cout << "\ruppercase? : [y/n] (enter [yYnN])";
			}
		} while (true);
		new_flags |= (uint32_t)password_generator::generate_password_flags::use_uppercase *
					 (use_uppercase == 'y' || use_uppercase == 'Y');

		char use_digits = 0;
		std::cout << "\ndigits?    : [y/n]";
		do {
			std::cin >> use_digits;
			if (use_digits == 'y' || use_digits == 'Y' || use_digits == 'n' || use_digits == 'N') {
				break;
			} else {
				std::cout << "\rdigits?    : [y/n] (enter [yYnN])";
			}
		} while (true);
		new_flags |= (uint32_t)password_generator::generate_password_flags::use_digits *
					 (use_digits == 'y' || use_digits == 'Y');

		char use_symbols = 0;
		std::cout << "\nsymbols?   : [y/n]";
		do {
			std::cin >> use_symbols;
			if (use_symbols == 'y' || use_symbols == 'Y' || use_symbols == 'n' || use_symbols == 'N') {
				break;
			} else {
				std::cout << "\rsymbols?   : [y/n] (enter [yYnN])";
			}
		} while (true);
		new_flags |= (uint32_t)password_generator::generate_password_flags::use_symbols *
					 (use_symbols == 'y' || use_symbols == 'Y');

		size_t seed = {0};
		std::cout << "\nseed?      : <unsigned integer>";
		bool cin_ok = false;
		do {
			cin_ok = (bool)(std::cin >> seed);
			if (cin_ok) {
				break;
			} else {
				std::cout << "\rseed?      : <unsigned integer> (enter a valid number)";
				std::cin.clear();
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			}
		} while (true);
		opt.seed = seed;

		size_t max_length = {32};
		std::cout << "\nmax_length?: <unsigned integer>";
		do {
			cin_ok = (bool)(std::cin >> max_length);
			if (cin_ok && max_length < 65535) {
				break;
			} else {
				std::cout << "\rmax_length?: <unsigned integer> (enter a valid number under 65535)";
				std::cin.clear();
				std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
			}
		} while (true);

		opt.flags      = (new_flags != uint32_t{0}) ? new_flags : opt.flags;
		opt.max_length = max_length;

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
	}

	return (int)out.result;
}
