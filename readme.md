# password_generator
a quick and dirty c++ password generator

```
usage:
    --generate         -g  : <salt> <login> <master_password> [options default: 0 --use-lowercase --use-uppercase --use-digits --use-symbols]
    --random           -r  : generates a random password      [options default: 0 --use-lowercase --use-uppercase --use-digits --use-symbols]
    --bytes            -b  : generates random bytes
options:
    <unsigned integer>     : set seed, use this to generate different passwords
    --use-lowercase    -l  : allows and requires at least one character [a-z]
    --use-uppercase    -u  : allows and requires at least one character [A-Z]
    --use-digits       -d  : allows and requires at least one character [0-9]
    --use-symbols      -s  : allows and requires at least one character [!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~]
    --help             -h  : shows usage
```

## build

`vcpkg install libsodium:x64-windows-static`

## usage

Build the executable then create shortcuts with commonly used parameters as needed.

EG:

```
    password_generator --random --use-lowercase --use-uppercase --use-digits --max-length 16
```

Will prompt about using symbols

Note:
The point of this repo is to be a fairly quick to configure personalized password generator (the configurable bits being in the .h and the quick and easy client in the .cpp).

I don't necessarily trust the cryptographic security of the functions included, I'm not a cryptographic expert. There are api functions specifically in `libsodium` for password hashing which I did not use and may be better. It appears those are designed with this kind of application in mind, supposedly they're configurable in not only how much state they can output but how difficult it is to repeat the hashing process. 

Here's an overview: in the current design I use an included hash function, this purportedly has an output size of 512 bits, of which 448 bits are being used to seed a xchacha20 stream. This* in theory is a state size of 56 bytes, shrinking the state size is not ideal, there's likely a decent way to make use of the full 512 bits. To me however since I'm thinking of this as a utility for generating passwords which may be used in web applications where there can be as weak as an 8 character minimum, I think 56 bytes worth of potential data streams is ok.

Some limitations: I made an assumption in this application that a xchacha20 stream (if cryptographically secure) is something I could treat as a random number generator. The output password should be a debiased selection of that stream of bytes to fit in the selected output alphabet, but without knowing how good xchacha can be treated in this way, I can't be sure it won't spit out completely garbage passwords at times. There's also the issue that I wrote this as a console application. In normal password hashing applications a salt is a randomly generated string of bytes which the user does not have to input, here I've no idea how to enter a truely random string of bytes as a parameter to a console application. I'm assuming the salt might be something like a mental note related to whatever application you're trying to generate a password for. In this sense the "salt" is really the password, which I'm not particuarly a fan of because I didn't set a minimum as to what that salt should be.

For ease of use this client writes to the clipboard (this is definitely not secure). I did consider the possibliity of the screen being captured so the console will not display the inputs when being prompted. As such I would not use the `--generate` or `-g` options. I'm not sure how well gaurded data that goes through `std::cin` or `std::cout` is. I'd like to gaurd against both screen readers and key loggers simultaneously, however I'm not sure how to do the latter. Overall I'm 0% confident in the application assuming there's already a malicious actor on your machine, this is a toy repo as is at best, if you're going to use it, you're using it at your own risk.
