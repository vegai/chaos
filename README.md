# chaos
Password metadata storager and xsalsa20 hasher. 

# installation / requirements

Rust stable (known to work on 1.8) needed to compile. 

A way to reliably protect the unencrypted master key file (~/.chaos/key). Perhaps
put it in a USB key that you always keep with you. Or keep it inside an encrypted volume that
you only open for the duration of usage. 

```
cargo install chaos
```

# usage

```
vegai@harmony ~ » ./chaos help
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

vegai@harmony ~ » chaos new meep # adds a salt and metadata only...
meep added
vegai@harmony ~ » chaos get meep # ... that's why master key is needed earliest here
Creating a new key in /home/vegai/.chaos/key
~3MRPc4;>l7/rC_;}QdTc"$c^;4xL:Gp
vegai@harmony ~ » chaos get meep
~3MRPc4;>l7/rC_;}QdTc"$c^;4xL:Gp
vegai@harmony ~ » chaos new simplesite -l 8 -f 3
simplesite added
vegai@harmony ~ » chaos get simplesite 
BwUShpSy
```

# security

I'm not a security expert. Dabbler, at most. 

If the master key file can be protected well enough, it might be quite secure. Unfortunately, protecting
single files from all intrusions on a typical desktop is nearly impossible.

Passwords are xsalsa20 hashes, generated from a metadata title, the master key and a salt, both of which
are kept unencrypted in ~/.chaos/

It might be more secure than storing your passwords in a plain text file. It's quite a lot more secure
than having "username123" as your password on every site.

# details

chaos creates and stores the following plain text things:
 - master key in ~/.chaos/key
 - password metadata in ~/.chaos/data.json

Having both these files means that you can get all the passwords with zero effort, so protecting them is important.

Password metadata contains structures of title, format, length, and generated salt. 

Actual passwords are not stored anywhere, but are computed by xsalsa20 and cut up based on wanted format.


# todo

- git integration 
- remove magic 1024 and just generate a required length string
- perhaps support a generic data field
- perhaps try to secure memory
