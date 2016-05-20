extern crate crypto;
extern crate rustc_serialize as serialize;
extern crate rand;
extern crate shellexpand;
#[macro_use]
extern crate clap;

use std::iter::repeat;
use crypto::salsa20::Salsa20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use serialize::base64;
use serialize::base64::{FromBase64, ToBase64};
use rand::{OsRng, Rng};
use clap::{Arg, App, SubCommand};
use std::process::exit;
use std::fs;

pub mod data;
use data::{Passwords, Password};

/*
// not used until I know how to work with Serde
#[derive(Debug)]
enum FormatChoices {
AlphaNumAndSymbols, // 1
AlphaNum,           // 2
AlphaOnly,          // 3
NumOnly             // 4
BinaryOnlyLol       // 5
}
*/
const DEFAULT_FORMAT: &'static str = "2";
const DEFAULT_LENGTH: &'static str = "32";
const SALT_LENGTH: usize = 24;
const KEY_LENGTH: usize = 32;
const GENERATED_INPUT_LENGTH: usize = 1024;


fn pack(allowed_chars: &str, hash: &[u8]) -> String {
    let source_len = allowed_chars.len();
    let mut output = String::new();
    for &byte in hash {
        let n = (byte % source_len as u8) as usize;
        output.push(allowed_chars.chars().nth(n).unwrap());
    }
    output
}

fn pack_into_password(hash: &[u8], format_choice: u8) -> String {
    match format_choice {
        1 => {
            pack("!\"#$%&'()*+,-./0123456789:;\
                  <=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
                 hash)
        }
        2 => {
            pack("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
                hash)
        }
        3 => pack("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", hash),
        4 => pack("0123456789", hash),
        5 => pack("01", hash), // stupider than the above, but not by much
        _ => panic!("Invalid format choice {}", format_choice),
    }
}

fn expand_to_at_least(wanted_length: usize, base: Vec<u8>) -> Vec<u8> {
    let mut buf = vec!();
    while buf.len() < wanted_length {
        buf.extend(&base);
    }
    buf
}

// Generates a new password bytestream.
//
// Algorithm:
//
// 1. Generate a random SALT_LENGTH byte salt
// 2. Repeat title until it reaches at least i bytes
// 3. Generate a cipher text using xsalsa20, with above string as input,
//    using given key and generated salt
//
//
fn generate_password(key: &[u8], salt: Vec<u8>, i: usize) -> Vec<u8> {
    let mut cipher = Salsa20::new_xsalsa20(&key, &salt);
    let clear_text = expand_to_at_least(i, salt);

    let mut buf: Vec<u8> = repeat(0).take(i).collect();
    cipher.process(&clear_text[0..i], &mut buf);
    buf
}

fn generate_salt() -> Vec<u8> {
    let mut rng = OsRng::new().expect("OsRng init failed");
    rng.gen_iter::<u8>().take(SALT_LENGTH).collect()
}

fn load_or_create_key(filename: &str) -> Vec<u8> {
    match Passwords::load_file(filename) {
        Ok(s) => s.from_base64().expect("Key base64 decoding failed"),
        Err(_) => {
            println!("Creating a new key in {}", filename);
            let mut rng = OsRng::new().expect("OsRng init failed");
            let new_key: Vec<u8> = rng.gen_iter::<u8>().take(KEY_LENGTH).collect();
            let key_base64 = new_key.to_base64(base64::STANDARD);
            Passwords::save_data(&key_base64, filename);
            Passwords::set_file_perms(filename, 0o400);
            new_key
        }
    }
}

fn create_data_dir(data_dir: &str) {
    fs::create_dir_all(data_dir.to_string())
        .expect(&format!("Creating data directory {} failed", data_dir));
    Passwords::set_file_perms(&data_dir, 0o700);
}


fn cut_password(pass: Vec<u8>, format: u8, length: u16) -> String {
    let packed_pass = pack_into_password(&*pass, format);
    packed_pass.chars().take(length as usize).collect()
}

fn main() {
    let matches = App::new("chaos")
                      .author("Vesa Kaihlavirta <vegai@iki.fi>")
                      .subcommand(SubCommand::with_name("ls").about("lists entries (default action if none specified)"))
                      .subcommand(SubCommand::with_name("rm")
                                      .about("remove entry")
                                      .arg(Arg::with_name("force")
                                               .long("force")
                                               .help("actually removes the entry")
                                               .value_name("force")
                                               .takes_value(false))
                                      .arg(Arg::with_name("title")
                                               .index(1)
                                               .required(true)))
                      .subcommand(SubCommand::with_name("get")
                                      .about("get entry")
                                      .arg(Arg::with_name("title")
                                               .index(1)
                                               .required(true)))
                      .subcommand(SubCommand::with_name("new")
                                      .arg(Arg::with_name("length")
                                               .short("l")
                                               .long("length")
                                               .help("wanted length of the password")
                                               .value_name("length")
                                               .takes_value(true))
                                      .arg(Arg::with_name("force")
                                               .long("force")
                                               .help("replace an existing entry")
                                               .value_name("force")
                                               .takes_value(false))
                                      .arg(Arg::with_name("format")
                                               .short("f")
                                               .long("format")
                                               .help("1=alphanumsymbol, 2=alphanum, 3=alpha, \
                                                      4=num, 5=lol")
                                               .value_name("format")
                                               .takes_value(true))
                                      .about("generate new entry")
                                      .arg(Arg::with_name("title")
                                               .index(1)
                                               .required(true)))
                      .get_matches();

    let data_dir = shellexpand::tilde("~/.chaos");
    let data_file_name = format!("{}/data.json", data_dir);
    let key_file_name = format!("{}/key", data_dir);
    create_data_dir(&data_dir);

    let mut old_data = Passwords::load_from_file(&data_file_name);


    // Functionality that does not require loading the key
    // ls
    if matches.subcommand_name() == None || matches.is_present("ls") {
        let mut titles: Vec<&String> = old_data.metadata.keys().collect();
        titles.sort();
        for title in titles {
            println!("{}", title);
        }
        return;
    }

    // rm
    if let Some(ref matches) = matches.subcommand_matches("rm") {
        let title = matches.value_of("title").unwrap();

        if old_data.title_exists(&title) && !matches.is_present("force") {
            println!("'{}' exists. --force to remove", title);
            exit(1);
        }

        old_data.metadata.remove(title);

        let metadata_string = old_data.to_string_pretty();
        Passwords::save_data(&metadata_string, &data_file_name);
        Passwords::set_file_perms(&data_file_name, 0o600);
        return;
    }

    // new
    if let Some(ref matches) = matches.subcommand_matches("new") {
        let title = matches.value_of("title").unwrap();

        if old_data.title_exists(&title) && !matches.is_present("force") {
            println!("'{}' exists already. --force to overwrite", title);
            exit(1);
        }

        let format = matches.value_of("format").unwrap_or(DEFAULT_FORMAT).parse::<u8>().unwrap();
        let length = matches.value_of("length").unwrap_or(DEFAULT_LENGTH).parse::<u16>().unwrap();

        let salt = generate_salt();
        let pd = Password {
            salt: salt.to_base64(base64::STANDARD),
            format: format,
            length: length,
        };
        old_data.insert(title, pd);
        let metadata_string = old_data.to_string_pretty();

        println!("{} added", title);
        Passwords::save_data(&metadata_string, &data_file_name);
        Passwords::set_file_perms(&data_file_name, 0o600);
        return;
    }

    // Functionality that does require loading the key
    // get
    let key = load_or_create_key(&key_file_name);
    if let Some(ref matches) = matches.subcommand_matches("get") {
        let title = matches.value_of("title").unwrap();
        let password = old_data.find_by_title_or_bail(&title);
        let decoded_salt: Vec<u8> = password.salt
                                            .from_base64()
                                            .expect("Salt base64 decoding failed");
        let pass = generate_password(&key, decoded_salt, GENERATED_INPUT_LENGTH);

        println!("{}", cut_password(pass, password.format, password.length));
        return;
    }

}

#[test]
fn test_cut_password() {
    let pass = vec!(1, 1, 88, 240, 120, 150, 13, 21, 34, 55);

    assert_eq!("11000011", cut_password(pass.clone(), 5, 8));
    assert_eq!("110000", cut_password(pass.clone(), 5, 6));

    assert_eq!("11800031", cut_password(pass.clone(), 4, 8));
    assert_eq!("118000", cut_password(pass.clone(), 4, 6));

    assert_eq!("bbKGqUnv", cut_password(pass.clone(), 3, 8));
    assert_eq!("bbKGqU", cut_password(pass.clone(), 3, 6));

    assert_eq!("bbA26Anv", cut_password(pass.clone(), 2, 8));
    assert_eq!("bbA26A", cut_password(pass.clone(), 2, 6));

    assert_eq!("\"\"yU;Y.6", cut_password(pass.clone(), 1, 8));
    assert_eq!("\"\"yU;Y", cut_password(pass.clone(), 1, 6));
}
