# chaos
Password metadata storager and xsalsa20 hasher

# installation / requirements

Rust nightly compiler is needed, because I use Serde with compiler plugins. Once those get in stable, I'll start
maintaining this against stable.

```
cargo install chaos
```

# usage

```
chaos help
chaos help new
chaos help get
chaos help ls
chaos help rm
```

# security

Who knows. Passwords are non-stored xsalsa20 hashes, generated from a metadata title, the master key and a salt.

It might be more secure than storing your passwords in a plain text file.

# details

chaos creates and stores the following plain text things:
 - master key in ~/.chaos/key
 - password metadata in ~/.chaos/data.json

Having both these files means that you can get all the passwords with zero effort, so protecting them is important.

Password metadata contains structures of title, format, length, and generated salt. 

Actual passwords are not stored anywhere, but are computed by xsalsa20 and cut up based on wanted format.


# todo

- zsh completion
- 
- remove magic 1024 and just generate a required length string
- perhaps support a generic data field
- perhaps try to secure memory
