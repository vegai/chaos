
# chaos
[![Build Status](https://travis-ci.org/vegai/chaos.svg?branch=master)](https://travis-ci.org/vegai/chaos)

Password metadata storager and xsalsa20 hasher. It generates and stores meats and salts and a master key, and 
is able to recall passwords by xsalsa20 hashing. Chaos also automatically makes git commits out of every
change to the JSON file.

# installation / requirements

Rust stable (known to work on 1.8) needed to compile. Git is required to be in path.

A way to reliably protect the unencrypted master key file (~/.chaos/key). Perhaps
put it in a USB key that you always keep with you. Or keep it inside an encrypted volume that
you only open for the duration of usage. 

```
cargo install chaos
```

# usage

```
vegai@discord ~ » chaos help
chaos 
Vesa Kaihlavirta <vegai@iki.fi>

USAGE:
    chaos [FLAGS] [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    get     get entry
    help    Prints this message or the help of the given subcommand(s)
    ls      lists entries (default action if none specified)
    new     generate new entry
    rm      remove entry
vegai@discord ~ » chaos new folder/meep
Initialized empty Git repository in /home/vegai/.chaos/.git/
[master (root-commit) ebb27d6] new folder/meep
 1 file changed, 10 insertions(+)
 create mode 100644 data.json
folder/meep added
vegai@discord ~ » chaos get folder/meep
Creating a new key in /home/vegai/.chaos/key
MB;W5N:O8U[)*+y']<".>NLO4g<rIp%*
vegai@discord ~ » chaos get folder/meep
MB;W5N:O8U[)*+y']<".>NLO4g<rIp%*
vegai@discord ~ » chaos new simplesite -l 8 -f 3
[master e11a4c8] new simplesite
 1 file changed, 6 insertions(+)
simplesite added
vegai@discord ~ » chaos get simplesite
eaxBRjVz
vegai@discord ~ » chaos new folder/meep
'folder/meep' exists already. --force to overwrite
vegai@discord ~ » chaos new folder/meep --force
[master 0c7ab32] new folder/meep
 1 file changed, 2 insertions(+), 2 deletions(-)
folder/meep added
vegai@discord ~ » chaos get folder/meep
09C8OdeTlCO)OQI1[#Q)lQ^0]]$4~]Q+
vegai@discord ~ » chaos rm folder/meep
'folder/meep' exists. --force to remove
vegai@discord ~ » chaos rm folder/meep --force
[master 0781633] rm folder/meep
 1 file changed, 6 deletions(-)
```

# security

I'm not a security expert. Dabbler, at most. 

If the master key file can be protected well enough, it might be quite secure. Unfortunately, protecting
single files from all intrusions on a typical desktop is nearly impossible.

Passwords are xsalsa20 hashes, generated from a generated meat, the master key and a salt, all of which
are kept unencrypted in ~/.chaos/

It might be more secure than storing your passwords in a plain text file. It's quite a lot more secure
than having "username123" as your password on every site.

# details

chaos creates and stores the following plain text things:
 - master key in ~/.chaos/key
 - password metadata in ~/.chaos/data.json

Having both these files means that you can get all the passwords with zero effort, so protecting them is important.

Password metadata contains structures of title, format, length, and generated meat+salt. 

Actual passwords are not stored anywhere, but are computed by xsalsa20 and cut up based on wanted format.

# todo

- (fairly) secure clipboard integration
- support editing the text field
- sync command for doing git pull/push
