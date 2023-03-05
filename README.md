ec - a command-line password manager

### Features:
* :lock: &nbsp; Secure! &nbsp; All data is encrypted with AES-256.
* :briefcase: &nbsp; Portable! &nbsp; A single executable using Python 3 and GnuPG 2.
* :open_book: &nbsp; Compatible! &nbsp; Import and export credentials in plaintext CSV files.
* :floppy_disk: &nbsp; Easy backups! &nbsp; Self-contained encrypted files can be copied anywhere.
* :old_key: &nbsp; Supports TOTP keys! &nbsp; Lock down your online accounts with 2-step verification.
* :game_die: &nbsp; Generates Passwords! &nbsp; Easily create strong, random passwords using flexible rules.

This is something I've been using and working on since at least 2010. It began life as a shell script, but in 2014 it was rewritten in Python. Earlier versions used OpenSSL/LibreSSL, some branches experimented with various lower-level cryptography libraries, but the modern sane solution is to just use GnuPG.

### Usage
```
usage: ec [-hv] [-f path] [-abcE] [-nN count] [-r rule] [-W path]
          [-p | -l | -o | -w | -d | -m | -i | -x] [path | name...]

GENERAL OPTIONS:
  -h                  display this help text and exit
  -v                  display version information and exit
  -f path             manage an encrypted password storage file
  -E                  treat account operands as regular expressions
  -a                  print all fields (default is Username, Password, TOTP)
  -c                  copy password to clipboard
  -b                  launch website in browser
  -n count            number of passwords to generate (default: 1)
  -r rule             password generator rule
  -W path             use a word list instead of random characters
  -N count            number of words to select from list (default: 4)

PASSWORD MANAGER COMMANDS:
  -p                  generate a password
  -l                  list account names
  -o name [name ...]  open accounts
  -w name [name ...]  create accounts
  -d name [name ...]  delete accounts
  -m                  change the master password
  -i path             import accounts from a CSV-formatted file
  -x path             export accounts to a CSV-formatted file

PASSWORD GENERATOR RULES:
  Default rule:       M(a12(lLds)2)M

  Syntax elements:
        a-zA-Z        random character from one of the sets below
        \             escape next character as literal
        [...]         custom character set, contents are literal
        <...>         logical group, useful for repeating
        (...)         shuffle group
        0-9...        repeat previous element

  Character sets:
        l             Letters     lower-case
        L             Letters     upper-case
        d             Digits      decimal
        m             Mixed-case  letters
        M             Mixed-case  alphanumeric
        n             No special  alphanumeric lower-case
        N             No special  alphanumeric upper-case
        s             Special     shell-safe special characters
        S             Special     printable special characters
        a             ASCII       shell-safe characters
        A             ASCII       printable characters
        h             Hexadecimal lower-case
        H             Hexadecimal upper-case
```

