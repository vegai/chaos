# chaos
Password metadata storager and salsa20 hasher

# usage

chaos help

# security

Who knows. Passwords are salsa20 hashes, generated from a metadata title, the generated key and a salt.

It might be more secure than storing your passwords in a plain text file.

# details

chaos creates and stores the following things:
 - master key in ~/.chaos/key
 - password metadata in ~/.chaos/data.json

Having both these files means that you can get all the passwords, so protecting them is important. Especially the key.

Password metadata contains structures of title, format, length, and generated salt.

Actual passwords are not stored anywhere, but are computed by salsa20 and cut up based on wanted format.



# todo

- title as key in the structure instead of a value (makes the json structure more sensible, and makes finds and deletes sane)
- ls command
- zsh completion
- clipboard integration (or perhaps just rely on xclip)
- perhaps support a generic data field

