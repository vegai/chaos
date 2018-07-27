//! common functionalities

extern crate crypto;
extern crate rand;

use std::env::set_current_dir;
use std::fs;
use std::fs::File;
use std::io;
use std::io::{Read, Write};
use std::iter::repeat;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use self::crypto::salsa20::Salsa20;
use self::crypto::symmetriccipher::SynchronousStreamCipher;
use self::rand::{OsRng, Rng};

use base64;

/// default salt length
const SALT_LENGTH: usize = 24;
/// default key length
const KEY_LENGTH: usize = 32;

/// generate an xsalsa20 based on key, meat and salt
pub fn generate_password(key: &[u8], meat: &[u8], salt: &[u8]) -> Vec<u8> {
    let mut cipher = Salsa20::new_xsalsa20(key, salt);
    let mut buf: Vec<u8> = repeat(0).take(meat.len()).collect();
    cipher.process(meat, &mut buf);
    buf
}

/// generate a new random salt
pub fn generate_salt() -> Vec<u8> {
    let mut rng = OsRng::new().expect("OsRng init failed");
    rng.gen_iter::<u8>().take(SALT_LENGTH).collect()
}

/// generate a new random meat, based on size
pub fn generate_meat(i: usize) -> Vec<u8> {
    let mut rng = OsRng::new().expect("OsRng init failed");
    rng.gen_iter::<u8>().take(i).collect()
}

/// load the private key, or generate a new one
pub fn load_or_create_key(filename: &str) -> Vec<u8> {
    if let Ok(s) = read_data(filename) {
        let s = s.lines().next().expect("Reading base64 key failed");
        base64::decode(s).expect("Key base64 decoding failed")
    } else {
        println!("Creating a new key in {}", filename);
        let mut rng = OsRng::new().expect("OsRng init failed");
        let new_key: Vec<u8> = rng.gen_iter::<u8>().take(KEY_LENGTH).collect();
        let key_base64 = base64::encode(&new_key); // .to_base64(base64::STANDARD);
        write_data(&key_base64, filename);
        set_file_perms(filename, 0o400);
        new_key
    }
}

/// ensure that the data dir exists
pub fn ensure_data_dir(data_dir: &str) {
    fs::create_dir_all(data_dir.to_string())
        .expect(&format!("Creating data directory {} failed", data_dir));
    set_file_perms(data_dir, 0o700);

    if !Path::new(data_dir).join(".git").exists() {
        set_current_dir(data_dir).expect("Failed to set dir to data dir");

        Command::new("git")
            .arg("init")
            .status()
            .expect("Failed to init data git repo");

        {
            let git_args = ["config", "user.email", "chaos"];
            Command::new("git")
                .args(&git_args)
                .status()
                .expect("Failed to set user.email");
        }

        {
            let git_args = ["config", "user.name", "chaos"];
            Command::new("git")
                .args(&git_args)
                .status()
                .expect("Failed to set user.name");
        }
    }
}

/// read all the data into String
pub fn read_data(path: &str) -> Result<String, io::Error> {
    let mut f = try!(File::open(path));
    let mut s = String::new();
    try!(f.read_to_string(&mut s));
    Ok(s)
}

/// commit data to VCS
pub fn commit_data(data_dir: &str, data_file: &str, commit_text: &str) {
    set_current_dir(data_dir).expect("Failed to set dir to data dir");

    let git_args = ["add", data_file].to_vec();

    Command::new("git")
        .args(&git_args)
        .status()
        .unwrap_or_else(|e| {
            panic!("Failed to add data file: {}", e);
        });

    let git_args = ["commit", "-m", commit_text].to_vec();
    Command::new("git")
        .args(&git_args)
        .status()
        .unwrap_or_else(|e| {
            panic!("Failed to git commit: {}", e);
        });
}

/// write data to file
pub fn write_data(data: &str, filename: &str) {
    let mut f = File::create(filename).expect("could not create data file");
    f.write_all(data.as_bytes())
        .expect("Data file write failed");
    f.write_all(b"\n").expect("Newline write failed!?");
    f.sync_all().expect("Sync failed");
}

/// set file permissions
pub fn set_file_perms(filename: &str, mode: u32) {
    let mut perms = fs::metadata(filename)
        .expect("Gettings perms failed")
        .permissions();
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
        let pass1 = generate_password(
            &[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24, 25, 26, 27, 28, 29, 30, 31, 32,
            ],
            &vec![1, 2],
            &vec![
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23,
                24,
            ],
        );
        assert_eq!(vec![230, 6], pass1);
    }
}
