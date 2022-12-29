# password_generator
a quick and dirty c++ password generator

```
usage:
    --generate         -g  : <salt> <login> <master_password> [options default: 0 --use-lowercase --use-uppercase --use-digits --use-symbols]
    --random           -r  : generates a random password      [options default: 0 --use-lowercase --use-uppercase --use-digits --use-symbols]
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