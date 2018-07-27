//! Chaos is a password hasher + metadata storager
#![cfg_attr(feature="clippy", feature(plugin))]
#![cfg_attr(feature="clippy", plugin(clippy))]
#![cfg_attr(feature="clippy", deny(clippy_pedantic))]
#![cfg_attr(feature="clippy", allow(print_stdout))]

extern crate shellexpand;
extern crate clap;
#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate base64;

use clap::{Arg, App, SubCommand};
use std::process::exit;

mod model;
mod common;

/// default password length
pub const DEFAULT_LENGTH: &'static str = "32";
/// default password format
pub const DEFAULT_FORMAT: &'static str = "1";

/// main main main
fn main() {
    let matches = App::new("chaos")
        .author("Vesa Kaihlavirta <vegai@iki.fi>")
        .subcommand(SubCommand::with_name("ls").about(
            "lists entries (default action if none specified)",
        ))
        .subcommand(
            SubCommand::with_name("rm")
                .about("remove entry")
                .arg(
                    Arg::with_name("force")
                        .long("force")
                        .help("actually removes the entry")
                        .value_name("force")
                        .takes_value(false),
                )
                .arg(Arg::with_name("title").index(1).required(true)),
        )
        .subcommand(SubCommand::with_name("get").about("get entry").arg(
            Arg::with_name("title").index(1).required(true),
        ))
        .subcommand(
            SubCommand::with_name("new")
                .arg(
                    Arg::with_name("length")
                        .short("l")
                        .long("length")
                        .help("wanted length of the password")
                        .value_name("length")
                        .takes_value(true),
                )
                .arg(
                    Arg::with_name("force")
                        .long("force")
                        .help("replace an existing entry")
                        .value_name("force")
                        .takes_value(false),
                )
                .arg(
                    Arg::with_name("format")
                        .short("f")
                        .long("format")
                        .help(
                            "1=alphanumsymbol, 2=alphanum, 3=alpha, \
                                                      4=num, 5=lol",
                        )
                        .value_name("format")
                        .takes_value(true),
                )
                .about("generate new entry")
                .arg(Arg::with_name("title").index(1).required(true)),
        )
        .get_matches();

    let data_dir = shellexpand::tilde("~/.chaos");
    let data_file_name = format!("{}/data.json", data_dir);
    let key_file_name = format!("{}/key", data_dir);
    common::ensure_data_dir(&data_dir);

    let mut old_data = model::Passwords::load_from_file(&data_file_name);

    // Functionality that does not require loading the key
    // ls
    if matches.subcommand_name() == None || matches.is_present("ls") {
        let mut titles: Vec<&String> = old_data.passwords.keys().collect();
        titles.sort();
        for title in titles {
            println!("{}", title);
        }
        return;
    }

    // rm
    if let Some(matches) = matches.subcommand_matches("rm") {
        let title = matches.value_of("title").expect("key title not found");

        if old_data.title_exists(title) && !matches.is_present("force") {
            println!("'{}' exists. --force to remove", title);
            exit(1);
        }

        old_data.passwords.remove(title);
        let commit_text = format!("rm {}", title);
        old_data.save_to_file(&data_dir, &data_file_name, &commit_text);
        return;
    }

    // new
    if let Some(matches) = matches.subcommand_matches("new") {
        let title = matches.value_of("title").expect("key title not found");

        if old_data.title_exists(title) && !matches.is_present("force") {
            println!("'{}' exists already. --force to overwrite", title);
            exit(1);
        }

        let format = matches
            .value_of("format")
            .unwrap_or(DEFAULT_FORMAT)
            .parse::<u8>()
            .expect("key format not found");
        let length = matches
            .value_of("length")
            .unwrap_or(DEFAULT_LENGTH)
            .parse::<u16>()
            .expect("key length not found");

        let salt = common::generate_salt();
        let meat = common::generate_meat(length as usize);
        let pd = model::Password {
            salt: base64::encode(&salt), // .to_base64(base64::STANDARD),
            meat: base64::encode(&meat), // meat.to_base64(base64::STANDARD),
            text: String::new(),
            format: format,
        };

        old_data.insert(title, pd);
        let commit_text = format!("new {}", title);
        old_data.save_to_file(&data_dir, &data_file_name, &commit_text);

        println!("{} added", title);
        return;
    }

    // Functionality that does require loading the key
    // get
    let key = common::load_or_create_key(&key_file_name);
    if let Some(matches) = matches.subcommand_matches("get") {
        let title = matches.value_of("title").expect("key title not found");
        let password = old_data.find_by_title_or_bail(title);
        let decoded_meat: Vec<u8> =
            base64::decode(&password.meat).expect("Meat base64 decoding failed");
        let decoded_salt: Vec<u8> =
            base64::decode(&password.salt).expect("Salt base64 decoding failed");
        let pass = common::generate_password(&key, &decoded_meat, &decoded_salt);

        println!("{}", password.cut(pass));
        return;
    }

}
