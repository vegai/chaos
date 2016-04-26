#![feature(custom_derive, plugin)]
#![plugin(serde_macros)]

extern crate crypto;
extern crate rustc_serialize as serialize;
extern crate serde;
extern crate serde_json;
extern crate dotenv;
extern crate rand;
extern crate shellexpand;

use std::iter::repeat;
use std::env;
use std::fs;
use std::io::{Read, Write};
use std::fs::File;
use std::os::unix::fs::PermissionsExt;
use crypto::salsa20::Salsa20;
use crypto::symmetriccipher::SynchronousStreamCipher;
use serialize::base64;
use serialize::base64::{FromBase64, ToBase64};
use dotenv::from_filename;
use rand::{OsRng, Rng};

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

#[derive(Serialize,Deserialize,Debug)]
struct Password {
    title: String,
    salt: String,
    format: u8
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

fn expand_to_at_least<'a>(wanted_length: usize, base: String) -> String {
    let mut buf = String::new();
    while buf.len() < wanted_length {
        buf.push_str(&base);
    }
    buf
}

/*

Generates a new password bytestream.

Algorithm:

1. Generate a random 8 byte salt
2. Concatenate title+password
3. Repeat above string until it reaches at least i bytes
4. Generate a cipher text using salsa20, with above string as input, using given key and generated salt
5. Return generated salt and cipher text

*/
fn generate_new_password_with_size(key: &[u8], title: &str, password: &str, i: usize) -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng::new().ok().expect("OsRng init failed");
    let salt : Vec<u8> = rng.gen_iter::<u8>().take(8).collect();

    let mut cipher = Salsa20::new(&key, &salt);
    let combined_text = format!("{}{}", title, password);
    let clear_text = expand_to_at_least(i, combined_text);

    let mut buf : Vec<u8> = repeat(0).take(i).collect();
    cipher.process(&clear_text.as_bytes()[0..i], &mut buf);

    ( salt, buf )
}

fn generate_new_password(key: &[u8], title: &str, password: &str) -> (Vec<u8>, Vec<u8>) {
    generate_new_password_with_size(key, title, password, 1024)
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
            let new_key : Vec<u8> = rng.gen_iter::<u8>().take(16).collect();
            let key_base64 = new_key.to_base64(base64::STANDARD);
            save_data(&key_base64, filename);
            //f.write_all(&key_base64).expect("Writing key failed");
            //f.sync_all().expect("Sync failed");
            set_file_perms(filename, 0o400);
            new_key
        }
    }
}

fn main() {
    from_filename(".chaos.conf").ok().expect("Configuration file needed");

    let data_dir_raw = env::var("CHAOS_DATA_DIR").ok().expect("CHAOS_DATA_DIR undefined");
    let data_dir = shellexpand::tilde(&data_dir_raw);
    let data_file_name = format!("{}/data.json", data_dir);
    let key_file_name = format!("{}/key", data_dir);
    fs::create_dir_all(data_dir.to_string()).ok().expect(&format!("Creating data directory {} failed", data_dir));
    set_file_perms(&data_dir, 0o700);

    let mut old_data = load_data(&data_file_name);

    // here would be UI
    let format = 5;
    let key = load_or_create_key(&key_file_name);
    println!("key is {:?}", key);
    let (salt, pass) = generate_new_password(&key, "title", "password");
    let pd = Password { title: "title".to_string(), salt: salt.to_base64(base64::STANDARD), format: format };

    old_data.push(pd);
    let metadata_string = serde_json::to_string_pretty(&old_data).unwrap();
    let packed_password = pack_into_password(&*pass, format);

    println!("password: {}", &packed_password[0..32]);
    save_data(&metadata_string, &data_file_name);
    set_file_perms(&data_file_name, 0o600);
}
