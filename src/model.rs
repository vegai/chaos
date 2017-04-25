use std::collections::HashMap;
use std::process::exit;

use serde_json;
use super::common;

#[derive(Serialize, Deserialize, Debug)]
pub struct Passwords {
    pub passwords: HashMap<String, Password>
}

impl Default for Passwords {
    fn default() -> Passwords {
        Passwords {
            passwords: HashMap::new(),
        }
    }
}

impl Passwords {
    pub fn title_exists(&self, title: &str) -> bool {
        self.passwords.contains_key(title)
    }

    pub fn insert(&mut self, title: &str, password: Password) {
        self.passwords.insert(title.to_string(), password);
    }

    pub fn load_from_file(path: &str) -> Passwords {
        match common::read_data(path) {
            Ok(d) => serde_json::from_str(&d).ok().unwrap_or_default(),
            Err(_) => Passwords::default(),
        }
    }

    pub fn save_to_file(&self, data_dir: &str, path: &str, commit_text: &str) {
        let data_json_string = self.to_string_pretty();
        common::write_data(&data_json_string, &path);
        common::set_file_perms(&path, 0o600);
        common::commit_data(&data_dir, &path, &commit_text);
    }

    pub fn to_string_pretty(&self) -> String {
        serde_json::to_string_pretty(self).unwrap()
    }

    pub fn find_by_title_or_bail<'a>(&'a self, title: &str) -> &'a Password {
        match self.passwords.get(title) {
            Some(password) => password,
            None => {
                println!("'{}' does not exist.", title);
                exit(2);
            }
        }
    }
}

#[derive(Serialize,Deserialize,Debug)]
pub struct Password {
    pub salt: String,
    pub meat: String,
    pub text: String,
    pub format: u8
}

impl Default for Password {
    fn default() -> Password {
        Password {
            salt: "".to_string(),
            meat: "".to_string(),
            text: "".to_string(),
            format: 1,
        }
    }
}

impl Password {
    fn pack_into_password(&self, hash: &[u8]) -> String {
        match self.format {
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
            5 => pack("01", hash),
            _ => panic!("Unknown format")
        }
    }

    pub fn cut(&self, pass: Vec<u8>) -> String {
        let packed_pass = self.pack_into_password(&*pass);
        packed_pass.chars().take(self.meat.len()).collect()
    }
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


#[cfg(test)]
mod tests {
    use super::*;

    impl Password {
        fn new_for_test(format: u8, meat: &str) -> Password {
            Password {
                salt: "".to_string(),
                meat: meat.to_string(),
                text: "".to_string(),
                format: format
            }
        }
    }

    #[test]
    fn test_cut_binary_password() {
        let pass = vec!(1, 1, 88, 240, 120, 150, 13, 21, 34, 55);
        let password = Password::new_for_test(5, "12345678");
        assert_eq!("11000011", password.cut(pass.clone()));


        let password = Password::new_for_test(5, "123456");
        assert_eq!("110000", password.cut(pass.clone()));
    }

    #[test]
    fn test_cut_numeral_password() {
        let pass = vec!(1, 1, 88, 240, 120, 150, 13, 21, 34, 55);
        let password = Password::new_for_test(4, "12345678");
        assert_eq!("11800031", password.cut(pass.clone()));

        let password = Password::new_for_test(4, "123456");
        assert_eq!("118000", password.cut(pass.clone()));
    }

    #[test]
    fn test_cut_alphaonly_password() {
        let pass = vec!(1, 1, 88, 240, 120, 150, 13, 21, 34, 55);
        let password = Password::new_for_test(3, "12345678");
        assert_eq!("bbKGqUnv", password.cut(pass.clone()));

        let password = Password::new_for_test(3, "123456");
        assert_eq!("bbKGqU", password.cut(pass.clone()));
    }

    #[test]
    fn test_cut_alphanum_password() {
        let pass = vec!(1, 1, 88, 240, 120, 150, 13, 21, 34, 55);
        let password = Password::new_for_test(2, "12345678");
        assert_eq!("bbA26Anv", password.cut(pass.clone()));

        let password = Password::new_for_test(2, "123456");
        assert_eq!("bbA26A", password.cut(pass.clone()));
    }

    #[test]
    fn test_cut_alphanumsym_password() {
        let pass = vec!(1, 1, 88, 240, 120, 150, 13, 21, 34, 55);
        let password = Password::new_for_test(1, "12345678");
        assert_eq!("\"\"yU;Y.6", password.cut(pass.clone()));

        let password = Password::new_for_test(1, "123456");
        assert_eq!("\"\"yU;Y", password.cut(pass.clone()));
    }

    #[test]
    fn test_passwords_title_exists() {
        let mut passwords = Passwords::default();
        assert_eq!(false, passwords.title_exists("meep"));

        let password = Password::default();
        passwords.insert("meep", password);
        assert_eq!(true, passwords.title_exists("meep"));

        assert_eq!("{\n  \"passwords\": {\n    \"meep\": {\n      \"salt\": \"\",\n      \"meat\": \"\",\n      \"text\": \"\",\n      \"format\": 1\n    }\n  }\n}", passwords.to_string_pretty());

        passwords.find_by_title_or_bail("meep");
    }
}
