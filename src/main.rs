#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate crypto;
extern crate rustc_serialize as serialize;
extern crate serde;
extern crate serde_json;
extern crate rand;
extern crate shellexpand;
extern crate clap;

use std::iter::repeat;
use std::fs;
use std::io::{Read, Write};
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use crypto::salsa20::Salsa20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use serialize::base64;
use serialize::base64::{FromBase64, ToBase64};
use rand::{OsRng, Rng};
use clap::{Arg, App, SubCommand};
use std::process::exit;

/* not used until I know how to work with Serde
#[derive(Debug)]
enum FormatChoices {
    AlphaNumAndSymbols, // 1
    AlphaNum,           // 2
    AlphaOnly,          // 3
    NumOnly             // 4
    BinaryOnlyLol       // 5
}
*/
const DEFAULT_FORMAT : &'static str = "1";
const DEFAULT_LENGTH : &'static str = "32";
const SALT_LENGTH : usize = 24;
const KEY_LENGTH : usize = 32;

#[derive(Serialize,Deserialize,Debug)]
struct Password {
    title: String,
    salt: String,
    format: u8,
    length: u8
}

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
        1 => pack("!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~", hash),
        2 => pack("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", hash),
        3 => pack("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ", hash),
        4 => pack("0123456789", hash),
        5 => pack("01", hash), // stupider than the above, but not by much
        _ => panic!("Invalid format choice {}", format_choice)
    }
}

fn expand_to_at_least<'a>(wanted_length: usize, base: &str) -> String {
    let mut buf = String::new();
    while buf.len() < wanted_length {
        buf.push_str(&base);
    }
    buf
}

/*

Generates a new password bytestream.

Algorithm:

1. Generate a random SALT_LENGTH byte salt
2. Repeat title until it reaches at least i bytes
3. Generate a cipher text using xsalsa20, with above string as input, using given key and generated salt

*/
fn generate_new_password_with_size(key: &[u8], title: &str, i: usize) -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng::new().ok().expect("OsRng init failed");
    let salt : Vec<u8> = rng.gen_iter::<u8>().take(SALT_LENGTH).collect();
    let pass = generate_password_with_salt(key, title, &salt, i);

    (salt, pass)
}

fn generate_password_with_salt(key: &[u8], title: &str, salt: &Vec<u8>, i: usize) -> Vec<u8> {
    let mut cipher = Salsa20::new_xsalsa20(&key, salt);
    let clear_text = expand_to_at_least(i, title);

    let mut buf : Vec<u8> = repeat(0).take(i).collect();
    cipher.process(&clear_text.as_bytes()[0..i], &mut buf);
    buf
}

fn generate_new_password(key: &[u8], title: &str) -> (Vec<u8>, Vec<u8>) {
    generate_new_password_with_size(key, title, 1024)
}

fn load_file(path: &str) -> Result<String, std::io::Error> {
    let mut f = try!(File::open(path));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    Ok(s)
}

fn load_data(path: &str) -> Vec<Password> {
    match load_file(path) {
        Ok(d) => serde_json::from_str(&d).unwrap_or(vec!()),
        Err(_) => vec!()
    }
}

fn save_data(data: &str, filename: &str) {
    let mut f = File::create(filename).unwrap();
    f.write_all(data.as_bytes()).expect("Data file write failed");
    f.write_all("\n".as_bytes()).expect("Newline write failed!");
    f.sync_all().expect("Sync failed");
}

fn set_file_perms(filename: &str, mode: u32) {
    let mut perms = fs::metadata(filename).expect("Gettings perms failed").permissions();
    perms.set_mode(mode);
    fs::set_permissions(filename, perms).expect("Setting permission failed");
}

fn load_or_create_key(filename: &str) -> Vec<u8> {
    match load_file(filename) {
        Ok(s) =>
            s.from_base64().expect("Key base64 decoding failed"),
        Err(_) => {
            println!("Creating a new key in {}", filename);
            let mut rng = OsRng::new().ok().expect("OsRng init failed");
            let new_key : Vec<u8> = rng.gen_iter::<u8>().take(KEY_LENGTH).collect();
            let key_base64 = new_key.to_base64(base64::STANDARD);
            save_data(&key_base64, filename);
            //f.write_all(&key_base64).expect("Writing key failed");
            //f.sync_all().expect("Sync failed");
            set_file_perms(filename, 0o400);
            new_key
        }
    }
}

fn create_data_dir(data_dir: &str) {
    fs::create_dir_all(data_dir.to_string()).ok().expect(&format!("Creating data directory {} failed", data_dir));
    set_file_perms(&data_dir, 0o700);
}

fn title_exists(passwords: &Vec<Password>, title: &str) -> bool {
    for password in passwords {
        if password.title == title {
            return true;
        }
    }
    false
}

fn find_password_by_title_or_bail<'a>(passwords: &'a Vec<Password>, title: &str) -> &'a Password {
    for &ref password in passwords {
        if password.title == title {
            return password;
        }
    }
    println!("'{}' does not exist.", title);
    exit(2);
}

fn cut_password(pass: Vec<u8>, format: u8, length: u8) -> String {
    let packed_pass = pack_into_password(&*pass, format);
    packed_pass.chars().take(length as usize).collect()
}

fn main() {
    let matches = App::new("chaos")
        .version("0.0")
        .author("Vesa Kaihlavirta <vegai@iki.fi>")
        .about("Manages passwords")
        .subcommand(SubCommand::with_name("ls")
                    .about("lists entries"))
        .subcommand(SubCommand::with_name("get")
                    .about("get entry")
                    .arg(Arg::with_name("title")
                         .index(1)
                         .required(true)))
        .subcommand(SubCommand::with_name("new")
                    .arg(Arg::with_name("length")
                         .short("l")
                         .long("length")
                         .help("length")
                         .value_name("length")
                         .takes_value(true))
                    .arg(Arg::with_name("force")
                         .long("force")
                         .help("force")
                         .value_name("force")
                         .takes_value(false))
                    .arg(Arg::with_name("format")
                         .short("f")
                         .long("format")
                         .help("format")
                         .value_name("format")
                         .takes_value(true))
                    .about("generate new entry")
                    .arg(Arg::with_name("title")
                         .index(1)
                         .required(true)
                    ))

        .get_matches();

    let data_dir = shellexpand::tilde("~/.chaos");
    let data_file_name = format!("{}/data.json", data_dir);
    let key_file_name = format!("{}/key", data_dir);
    create_data_dir(&data_dir);

    let mut old_data = load_data(&data_file_name);


    // Functionality that does not require loading the key
    if matches.is_present("ls") {
        println!("ls");
        return;
    }

    // Functionality that does require loading the key
    let key = load_or_create_key(&key_file_name);
    if let Some(ref matches) = matches.subcommand_matches("get") {
        let title = matches.value_of("title").unwrap();
        let password = find_password_by_title_or_bail(&old_data, &title);
        let decoded_salt : Vec<u8> = password.salt.from_base64().expect("Salt base64 decoding failed");
        let pass = generate_password_with_salt(&key, title, &decoded_salt, 1024);

        println!("{}", cut_password(pass, password.format, password.length));
        return;
    }

    if let Some(ref matches) = matches.subcommand_matches("new") {
        let title = matches.value_of("title").unwrap();

        if title_exists(&old_data, &title) {
            if matches.is_present("force") {
                println!("Force asked");
                exit(1);
            } else {
                println!("'{}' exists already. --force to overwrite", title);
                exit(1);
            }
        }

        let format = matches.value_of("format").unwrap_or(DEFAULT_FORMAT).parse::<u8>().unwrap();
        let length = matches.value_of("length").unwrap_or(DEFAULT_LENGTH).parse::<u8>().unwrap();

        let (salt, pass) = generate_new_password(&key, title);
        let pd = Password { title: title.to_string(), salt: salt.to_base64(base64::STANDARD), format: format, length: length };
        old_data.push(pd);
        let metadata_string = serde_json::to_string_pretty(&old_data).unwrap();

        println!("{}", title);
        println!("{}", cut_password(pass, format, length));
        save_data(&metadata_string, &data_file_name);
        set_file_perms(&data_file_name, 0o600);
        return;
    }

}
