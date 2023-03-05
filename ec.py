#!/usr/bin/env python3
# ec - a password manager
#
# Copyright (c) Robert Thralls
#
# Permission to use, copy, modify, and/or distribute this software
# for any purpose with or without fee is hereby granted.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL
# WARRANTIES WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE
# AUTHOR BE LIABLE FOR ANY SPECIAL, DIRECT, INDIRECT, OR
# CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
# LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
# NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
# CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

r"""
ec - a command-line password manager

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
"""

import argparse
import base64
import binascii
import getpass
import hashlib
import hmac
import os
import platform
import random
import re
import struct
import subprocess
import sys
import time
import webbrowser

__version__ = '2.4.1'


class PassGen():

    """Object for generating random passwords."""

    def __init__(self, rule=None, wlist=None, words=None):
        """Initialize the password generator."""
        self.rule = rule or 'M(a12(lLds)2)M'
        self._elements = None  # chargen rule parsing cache
        self.sets = {
            'l': 'abcdefghijklmnopqrstuvwxyz',
            'L': 'ABCDEFGHIJKLMNOPQRSTUVWXYZ',
            'd': '0123456789',
            's': '%+-./:=@_',  # non-obvious exclusions: comma and caret
            'S': r"""%+-./:=@_!"#$&'()*,;<>?[\]^`{|}~""",
            'h': '0123456789abcdef',
            'H': '0123456789ABCDEF',
        }
        self.sets['m'] = self.sets['l'] + self.sets['L']
        self.sets['M'] = self.sets['m'] + self.sets['d']
        self.sets['n'] = self.sets['l'] + self.sets['d']
        self.sets['N'] = self.sets['L'] + self.sets['d']
        self.sets['a'] = self.sets['M'] + self.sets['s']
        self.sets['A'] = self.sets['M'] + self.sets['S']
        self.wlist = wlist
        self.words = words

    def generate(self):
        """Generate a random password string."""
        return self._wordgen() if self.wlist else self._chargen()

    def _wordgen(self):
        try:
            with open(self.wlist, 'r') as f:
                wordlist = [line.strip().capitalize() for line in f]
        except IOError:
            _err(f"failed to open wordlist: '{self.wlist}'")
        return ' '.join(random.choice(wordlist) for i in range(self.words))

    def __parserule(self, idx=0, flag=None):
        # process a password generator rule string
        # output is a list of nested element tuples
        elements = []
        while idx < len(self.rule):
            char = self.rule[idx]
            if char == flag:
                # end recursion, go back up a level
                break
            elif char == '\\':
                # treat next character as literal
                key, value = 'escape', self.rule[idx + 1]
                idx += 1
            elif flag == ']':
                # while processing a custom set, all characters are literal
                key, value = 'escape', char
            elif char in self.sets:
                # character is a pre-defined set placeholder
                key, value = 'set', char
            elif char == '<':
                # angle brackets denote groups where order is preserved
                recurse, idx = self.__parserule(idx=idx + 1, flag='>')
                key, value = 'group', recurse
            elif char == '(':
                # parentheses denote groups that are shuffled
                recurse, idx = self.__parserule(idx=idx + 1, flag=')')
                key, value = 'shuffle', recurse
            elif char == '[':
                # square brackets denote groups defining a custom set
                # only one character is selected from the set at a time
                recurse, idx = self.__parserule(idx=idx + 1, flag=']')
                key, value = 'custom', ''.join(c[1] for c in recurse)
            elif char in ('>', ')', ']'):
                # encountered the end of a group without a beginning
                _err(f"misplaced '{char}'")
            elif char.isdecimal():
                # repeat the previous (completed) element
                if len(elements) < 1:
                    # we can't repeat at the beginning of a rule or group
                    _err('misplaced repeat')
                count = re.sub(r'[^0-9].*', '', ''.join(self.rule[idx:]))
                key, value = 'repeat', int(count)
                idx += len(count) - 1
            else:
                _err(f"unrecognized character: '{char}'")
            elements.append((key, value))
            idx += 1
        return elements, idx

    def _chargen(self, elements=None):
        # process element tuples from __parserule()
        # output is a password string
        if self._elements is None:
            # cache the results for subsequent runs
            self._elements = self.__parserule()[0]
        # read from args first to allow recursing
        elements = elements or self._elements
        password = []
        for i, element in enumerate(elements):
            key, value = element
            if key == 'escape':
                # value is a single literal character
                password.append(value)
            elif key == 'set':
                # value refers to a pre-defined character set
                # select a random character from that set
                password.append(random.choice(self.sets[value]))
            elif key == 'group':
                # value is a nested set of elements to process
                password.append(''.join(self._chargen(value)))
            elif key == 'shuffle':
                # same as group, but shuffle the results after recursing
                recursed = self._chargen(value)
                recursed = random.sample(recursed, k=len(recursed))
                password.append(''.join(recursed))
            elif key == 'custom':
                # value is a user-defined character set
                # select a random character from that set
                password.append(random.choice(value))
            elif key == 'repeat':
                # value is the number of times to repeat
                # be sure to repeat the previous element tuple,
                # not its resulting password string
                repeat = [elements[i - 1]]
                for j in range(value - 1):
                    password.append(''.join(self._chargen(repeat)))
        return ''.join(password)


class Account():

    """Object for managing account credentials."""

    def __init__(self, name, fields=None, pg=None):
        """Initialize an account."""
        self.name = name
        self.fields = [] if fields is None else fields
        self.pg = PassGen() if pg is None else pg

    def print(self, **kwargs):
        """Print account fields."""
        default_fields = ['Username', 'Password', 'TOTP', 'TOTP6', 'TOTP8']
        if kwargs.get('browser', False):
            default_fields.append('Website')
        print()
        self.__indent('Account', self.name)
        for i in range(0, len(self.fields), 2):
            field = self.fields[i]
            if not kwargs.get('print_all', False):
                if field not in default_fields:
                    continue
            self.__indent(field)
            try:
                value = self.fields[i + 1]
            except IndexError:
                _err('unexpected end of fields')
            # True:  calculate a response (open)
            # False: dump the raw key (write and export)
            if kwargs.get('totp', True):
                if field in ('TOTP', 'TOTP6', 'TOTP8'):
                    digits = 8 if field == 'TOTP8' else 6
                    value = ' '.join(key2totp(value, digits=digits))
            print(value)
            if kwargs.get('clip', False):
                if field == 'Password':
                    copy2clip(value)
            if kwargs.get('browser', False):
                if field == 'Website':
                    webbrowser.open_new_tab(value)

    def prompt(self, fields=None):
        """Interactive prompts to input account fields."""
        if self.fields:
            self.print(print_all=True, totp=False)
            print('\nOverwrite this account? (y/N): ', end='', flush=True)
            if input().lower() not in ['y', 'yes']:
                return
            if fields:
                self.fields = fields
                self.print(print_all=True, totp=False)
                return
        print()
        self.__indent('Account', self.name)
        for field in ('Username', 'Password', 'Website'):
            self.__setfield(field)
        while True:
            print('New field name: ', end='', flush=True)
            field = input()
            if not field:
                break
            self.__setfield(field)

    def __indent(self, field, value=None, indent=12):
        field = f'{field}:'
        if len(field) < indent:
            indent -= len(field)
        else:
            field = f'{field}\n'
        print(f"{field}{' ' * indent}", end='', flush=True)
        if value:
            print(value)

    def __setfield(self, field):
        self.__indent(field)
        value = input()
        if field not in ('Website', 'TOTP', 'TOTP6', 'TOTP8'):
            if not value:
                value = self.pg.generate()
                self.__indent(field, value)
        if value:
            self.fields += (field, value)


class ECStore():

    """Object for managing a password storage file."""

    def __init__(self, path=None, accounts=None, master=None, PassGen=None):
        """Initialize ECStore."""
        self.path = path
        self.accounts = {} if accounts is None else accounts
        self.master = master
        self.pg = PassGen

    def load(self, path=None, decrypt=True):
        """Load accounts from a file."""
        if path is None:
            if self.path is None:
                _err('no input file path provided')
            path = self.path
            decrypt = True
        content = self._read(path)
        if not content:
            return
        if decrypt:
            content = self._decrypt(content)
        self._merge(accounts=self._csv2dict(content, b64decode=decrypt))

    def save(self, path=None, encrypt=True):
        """Save accounts to a file."""
        if path is None:
            if self.path is None:
                _err('no output file path provided')
            path = self.path
            encrypt = True
        content = self._dict2csv(b64encode=encrypt)
        if path == '-':
            print(content)
            return
        if encrypt:
            content = self._encrypt(content)
        self._write(path, content)

    def _read(self, path):
        if not os.path.isfile(path):
            return
        try:
            # binary mode avoids autotranslation of newlines
            with open(path, 'rb') as f:
                return f.read().decode()
        except IOError as e:
            _err(e, f"read error: '{path}'")

    def _write(self, path, content):
        try:
            dirname = os.path.realpath(os.path.dirname(path))
            os.makedirs(dirname, exist_ok=True)
            # binary mode avoids autotranslation of newlines
            with open(path, 'wb') as f:
                f.write(content.encode())
        except IOError as e:
            _err(e, f"write error: '{path}'")

    def _decrypt(self, ciphertext):
        if not which('gpg'):
            _err('command not found: gpg')
        if not self.master:
            self.getpass(confirm=False)
        cmd = """gpg -d --no-symkey-cache --batch
            --passphrase-fd 0 --pinentry-mode loopback""".split()
        data = f'{self.master}\n{ciphertext}\n'.encode()
        run_opts = {'capture_output': True, 'check': True}
        try:
            res = subprocess.run(cmd, input=data, **run_opts)
        except subprocess.CalledProcessError:
            _err('decryption error')
        return res.stdout.decode()

    def _encrypt(self, plaintext):
        if not which('gpg'):
            _err('command not found: gpg')
        if not self.master:
            print()
            self.getpass(confirm=True)
        cmd = """gpg -c -a --no-symkey-cache --batch
            --cipher-algo AES256 --digest-algo SHA512
            --passphrase-fd 0 --pinentry-mode loopback""".split()
        data = f'{self.master}\n{plaintext}'.encode()
        run_opts = {'capture_output': True, 'check': True}
        try:
            res = subprocess.run(cmd, input=data, **run_opts)
        except subprocess.CalledProcessError:
            _err('encryption error')
        return res.stdout.decode()

    def _csv2dict(self, content, b64decode=True):
        # CSV formatting requirements:
        #   1. ALL fields MUST be double-quoted
        #   2. ALL lines MUST be \r\n-separated
        #   3. EACH double quote character INSIDE a double-quoted value
        #      MUST be escaped with a double quote character
        #
        # Known issue:
        #   CSV imports will fail if double-quoted values contain
        #   double-quoted commas ('","') or \r\n ('"\r\n"').
        #   The on-disk format avoids this with base64 encoding,
        #   so such values are permitted by interactive prompts.
        accounts = {}
        csv = content.strip()
        csv = re.sub(r'""', '"', csv)
        csv = csv.removeprefix('"')  # <- do these only ONCE each...
        csv = csv.removesuffix('"')  # <-    ...don't use strip('"')
        for line in csv.split('"\r\n"'):
            row = []
            for field in line.split('","'):
                if b64decode:
                    try:
                        field = self._b64decode(field)
                    except binascii.Error:
                        _err('base64 decoding error')
                row.append(field)
            accounts[row[0]] = Account(row[0], fields=row[1:], pg=self.pg)
        return accounts

    def _dict2csv(self, b64encode=True):
        csv = []
        for name, account in self.accounts.items():
            fields = account.fields
            row = []
            if b64encode:
                name = self._b64encode(name)
            row.append(f'"{name}"')
            for field in fields:
                if b64encode:
                    field = self._b64encode(field)
                else:
                    field = re.sub('"', '""', field)
                row.append(f'"{field}"')
            csv.append(','.join(row))
        return '\r\n'.join(csv)

    def _b64encode(self, msg):
        return base64.b64encode(msg.encode()).decode()

    def _b64decode(self, msg):
        return base64.b64decode(msg).decode()

    def _merge(self, accounts={}):
        for name, account in accounts.items():
            if name in self.accounts:
                self.accounts[name].prompt(fields=account.fields)
            else:
                self.accounts[name] = account

    def getpass(self, confirm=False):
        """Get the master passphrase."""
        if not confirm:
            print('Master passphrase: ', end='', flush=True)
            self.master = getpass.getpass('')
            return
        while True:
            print('Set the new master passphrase: ', end='', flush=True)
            self.master = getpass.getpass('')
            if not confirm:
                break
            print('Confirm the master passphrase: ', end='', flush=True)
            if self.master == getpass.getpass(''):
                break
            print('Passphrases did not match.')

    def list(self):
        """List all account names."""
        for name in sorted(self.accounts):
            print(name)

    def delete(self, name):
        """Delete an account."""
        if name in self.accounts:
            del self.accounts[name]
        else:
            _err(f"account not found: '{name}'")

    def new(self, name):
        """Create a new account."""
        if name not in self.accounts:
            self.accounts[name] = Account(name, pg=self.pg)
        self.accounts[name].prompt()

    def search(self, *searches, **kwargs):
        """Return a list of matching account names."""
        names = []
        for name in sorted(self.accounts):
            for search in searches:
                if kwargs.get('regex', False):
                    if re.search(search, name):
                        names.append(name)
                elif name == search:
                    names.append(search)
                    break
        return names

    def open(self, *names, **kwargs):
        """Print fields for a specified account."""
        if 1 < len(names):
            kwargs['clip'] = False
        for name in names:
            if name in self.accounts:
                self.accounts[name].print(**kwargs)


def _err(*errors, exit=True):
    if errors:
        if 1 < len(errors):
            for e in errors[:-1]:
                print(f'{e}\n', sep='')
        print(f'{sys.argv[0]}: {errors[-1]}')
    if exit:
        sys.exit(1)


def _parsehelp(helptext):
    # parses our nice pydoc help text and feeds it into argparse
    helptext = helptext.strip().split('\n')
    usage, opts, epilog = None, None, None
    for i, line in enumerate(helptext):
        line = line.strip()
        if line == '':
            continue
        elif line.lower().startswith('usage: '):
            # found the usage line, split on next blank line
            j = i + 1
            while j < len(helptext):
                if helptext[j].strip() == '':
                    usage = '\n'.join(helptext[i:j])
                    break
                j += 1
        elif re.sub(r'[^A-Z0-9 :]', '', line) == line:
            # upon the first heading, divide the remaining text
            # by searcing backwards to find the last option line
            j = len(helptext) - 1
            while i < j:
                if helptext[j].strip().startswith('-'):
                    opts = '\n'.join(helptext[i:j + 1])
                    epilog = '\n'.join(helptext[j + 1:])
                    break
                j -= 1
        if usage and opts and epilog:
            break
    pargs = {
        'prog': 'ec',
        'usage': usage.removeprefix('usage: '),
        'epilog': epilog,
        'add_help': False,
        'formatter_class': argparse.RawTextHelpFormatter}
    p = argparse.ArgumentParser(**pargs)
    for line in opts.split('\n'):
        line = line.strip()
        if line == '':
            continue
        if line == re.sub(r'[^A-Z0-9 :]', '', line):
            # found a heading, use it as an argparser group
            # since we're already going in order, we can reuse
            # the variable name here for subsequent groups
            pg = p.add_argument_group(line.removesuffix(':'))
            continue
        words = line.split(' ')
        if words[0] == '-h':
            conf = {'action': 'help'}
        elif words[0] == '-v':
            conf = {'action': 'version', 'version': __version__}
        elif words[1] == '':
            # no metavariable found, treat as boolean
            conf = {'action': 'store_true'}
        elif words[2] == '...]':
            # option accepts multiple optional arguments
            #   -x [example ...]
            conf = {'nargs': '*',
                    'metavar': words[1].removeprefix('[')}
        else:
            # option requires exactly one argument
            #   -x example
            conf = {'metavar': words[1]}
        if words[3] == '...]':
            # option expects at least one argument
            #   -x example [example ...]
            conf['nargs'] = '+'
        for i in reversed(range(len(words) - 1)):
            # check for default values
            #   (default: 1)
            if words[i] == '(default:':
                conf['default'] = int(words[i + 1].removesuffix(')'))
                conf['type'] = int
                break
        for i in range(len(words)):
            # set help to everything after the first empty word
            if not words[i] and words[i + 1]:
                conf['help'] = ' '.join(words[i + 1:])
                break
        pg.add_argument(words[0], **conf)
    p.add_argument('operands', nargs='*', help=argparse.SUPPRESS)
    return p, vars(p.parse_args())


def _help(p, msg=None):
    p.print_help()
    if msg:
        print(f'\nec: {msg}')
    sys.exit(1)


def copy2clip(data):
    """Copy a string to the host system clipboard."""
    plat = platform.system()
    if plat == 'Linux':
        program = 'xclip'
    elif plat == 'Darwin':
        program = 'pbcopy'
    elif plat == 'Windows':
        program = 'clip'
    else:
        return
    data = f'{data}'.encode()
    run_opts = {'capture_output': True, 'check': True}
    if which(program):
        try:
            subprocess.run(program, input=data, **run_opts)
        except subprocess.CalledProcessError:
            pass


def key2totp(key, digits=6, window=1):
    """Return a list of OATH TOTP responses."""
    key = re.sub(' ', '', str(key))
    # TOTP algorithm as defined in RFC 6238.
    t = int(time.time())  # seconds since UNIX epoch
    X = 30                # time step in seconds
    T = int(t/X)          # current number of time steps
    w = int(window)       # valid step window
    D = int(digits)       # token length (6 or 8)
    a = hashlib.sha1      # hashing algorithm
    try:
        K = bytes.fromhex(key)  # try hexadecimal
    except ValueError:
        try:
            K = base64.b32decode(key, casefold=True)  # try base32
        except Exception:
            return [key]  # give up
    W = [T]
    if 0 < w:
        W = list(range(T, T + w))
    elif w < 0:
        W = list(range(T + w, T))
    responses = []
    for c in W:
        C = struct.pack('>Q', int(c))   # counter
        h = hmac.new(K, C, a).digest()  # HMAC of key and counter
        i = h[-1] & 0xF                 # get 4 least-significant bits
        i = h[i:i + 4]                  # get 4 bytes, offset
        i, = struct.unpack('>I', i)     # convert to integer
        i = i & 0x7FFFFFFF              # discard most-significant bit
        i = str(i)                      # convert to decimal string
        i = i[-D:].zfill(D)             # zero-padded D digits from end
        responses.append(i)
    return responses


def which(program):
    cmd = 'which', program
    if platform.system() == 'Windows':
        cmd = 'where', program
    run_opts = {'capture_output': True, 'check': True}
    try:
        res = subprocess.run(cmd, **run_opts)
    except subprocess.CalledProcessError:
        return None
    return res.stdout.decode().strip()


def main(argv=None):
    argv = argv or []
    p, args = _parsehelp(__doc__)
    if len(argv) == 0:
        _help(p)
    # argument sanity checks
    for arg in 'plowdmix':
        if args[arg]:
            if 'cmd' in args:
                _help(p, 'too many password manager commands')
            args['cmd'] = arg
    if 'cmd' not in args:
        if args['f'] and args['operands']:
            args.update({'cmd': 'o', 'o': []})
        else:
            _help(p)
    if args['cmd'] in 'owd':
        args[args['cmd']] += args['operands']
    # generate passwords
    if args['p']:
        if args['n'] < 1:
            _help(p)
        pg = PassGen(rule=args['r'], wlist=args['W'], words=args['N'])
        if 1 < args['n']:
            args['c'] = False
        for i in range(args['n']):
            password = pg.generate()
            print(password)
            if args['c']:
                copy2clip(password)
        sys.exit(0)
    # manage an encrypted password storage file
    if not args['f']:
        _help(p, 'password management commands expect -f')
    ecs = ECStore(path=args['f'])
    ecs.load()
    if args['m']:
        ecs.getpass(confirm=True)
    elif args['l']:
        ecs.list()
    elif args['o']:
        if args['E']:
            names = []
            for operand in args['o']:
                names += ecs.search(operand, regex=True)
        else:
            names = args['o']
        if 1 < len(names):
            args['c'] = False
        o_opts = {'print_all': args['a'], 'clip': args['c'],
                  'browser': args['b']}
        ecs.open(*names, **o_opts)
    elif args['w']:
        for name in args['w']:
            ecs.new(name)
    elif args['d']:
        for name in args['d']:
            ecs.delete(name)
    elif args['i']:
        ecs.load(path=args['i'], decrypt=False)
    elif args['x']:
        ecs.save(path=args['x'], encrypt=False)
    if args['cmd'] in 'mwdi':
        ecs.save()
    sys.exit(0)


if __name__ == '__main__':
    try:
        sys.exit(main(argv=sys.argv[1:]))
    except KeyboardInterrupt:
        print()
        sys.exit(1)
