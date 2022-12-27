# password_generator
a quick and dirty c++ password generator

```
usage: <salt> <login> <master_password> [options default: 0 --use-lowercase --use-uppercase --use-digits --use-symbols]
         <unsigned integer> : set seed, use this to generate different passwords
        --use-lowercase : allows and requires at least one character [a-z]
        --use-uppercase : allows and requires at least one character [A-Z]
        --use-digits    : allows and requires at least one character [0-9]
        --use-symbols   : allows and requires at least one character [!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~]
```