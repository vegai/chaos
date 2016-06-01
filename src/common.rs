extern crate crypto;
extern crate rustc_serialize as serialize;
extern crate rand;

use std::iter::repeat;
use std::fs;
use std::io;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;

use self::crypto::salsa20::Salsa20;
use self::crypto::symmetriccipher::SynchronousStreamCipher;
use self::serialize::base64;
use self::serialize::base64::{FromBase64, ToBase64};
use self::rand::{OsRng, Rng};

const SALT_LENGTH: usize = 24;
const KEY_LENGTH: usize = 32;

pub fn generate_password(key: &[u8], meat: Vec<u8>, salt: Vec<u8>) -> Vec<u8> {
    let mut cipher = Salsa20::new_xsalsa20(&key, &salt);
    let mut buf: Vec<u8> = repeat(0).take(meat.len()).collect();
    cipher.process(&meat, &mut buf);
    buf
}

pub fn generate_salt() -> Vec<u8> {
    let mut rng = OsRng::new().expect("OsRng init failed");
    rng.gen_iter::<u8>().take(SALT_LENGTH).collect()
}

pub fn generate_meat(i: usize) -> Vec<u8> {
    let mut rng = OsRng::new().expect("OsRng init failed");
    rng.gen_iter::<u8>().take(i).collect()
}

pub fn load_or_create_key(filename: &str) -> Vec<u8> {
    match load_file(filename) {
        Ok(s) => s.from_base64().expect("Key base64 decoding failed"),
        Err(_) => {
            println!("Creating a new key in {}", filename);
            let mut rng = OsRng::new().expect("OsRng init failed");
            let new_key: Vec<u8> = rng.gen_iter::<u8>().take(KEY_LENGTH).collect();
            let key_base64 = new_key.to_base64(base64::STANDARD);
            save_data(&key_base64, filename);
            set_file_perms(filename, 0o400);
            new_key
        }
    }
}

pub fn ensure_data_dir(data_dir: &str) {
    fs::create_dir_all(data_dir.to_string())
        .expect(&format!("Creating data directory {} failed", data_dir));
    set_file_perms(&data_dir, 0o700);
}

pub fn load_file(path: &str) -> Result<String, io::Error> {
    let mut f = try!(File::open(path));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    Ok(s)
}

pub fn save_data(data: &str, filename: &str) {
    let mut f = File::create(filename).unwrap();
    f.write_all(data.as_bytes()).expect("Data file write failed");
    f.write_all(b"\n").expect("Newline write failed!?");
    f.sync_all().expect("Sync failed");
}

pub fn set_file_perms(filename: &str, mode: u32) {
    let mut perms = fs::metadata(filename).expect("Gettings perms failed").permissions();
    perms.set_mode(mode);
    fs::set_permissions(filename, perms).expect("Setting permission failed");
}



#[cfg(test)]
mod tests {
    use super::*; 

    #[test]
    fn test_generate_salt() {
        let salt1 = generate_salt();
        let salt2 = generate_salt();
        assert!(salt1 != salt2);
    }

    #[test]
    fn test_generate_meat() {
        let meat1 = generate_meat(8);
        let meat2 = generate_meat(8);
        assert!(meat1 != meat2);
        assert_eq!(8, meat1.len());
        assert_eq!(8, meat2.len());
    }

    #[test]
    fn test_generate_password() {
        let pass1 = generate_password(&[1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32], vec!(1, 2), vec!(1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24));
        assert_eq!(vec!(230, 6), pass1);

    }
}
