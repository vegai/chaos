
extern crate rustc_serialize as serialize;
extern crate shellexpand;
#[macro_use]
extern crate clap;

use clap::{Arg, App, SubCommand};
use std::process::exit;
use serialize::base64;
use serialize::base64::{FromBase64, ToBase64};

mod model;
mod common;

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
    common::create_data_dir(&data_dir);

    let mut old_data = model::Passwords::load_from_file(&data_file_name);


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
        model::Passwords::save_data(&metadata_string, &data_file_name);
        model::Passwords::set_file_perms(&data_file_name, 0o600);
        return;
    }

    // new
    if let Some(ref matches) = matches.subcommand_matches("new") {
        let title = matches.value_of("title").unwrap();

        if old_data.title_exists(&title) && !matches.is_present("force") {
            println!("'{}' exists already. --force to overwrite", title);
            exit(1);
        }

        let format = matches.value_of("format").unwrap_or(common::DEFAULT_FORMAT).parse::<u8>().unwrap();
        let length = matches.value_of("length").unwrap_or(common::DEFAULT_LENGTH).parse::<u16>().unwrap();

        let salt = common::generate_salt();
        let pd = model::Password {
            salt: salt.to_base64(base64::STANDARD),
            format: format,
            length: length,
        };
        old_data.insert(title, pd);
        let metadata_string = old_data.to_string_pretty();

        println!("{} added", title);
        model::Passwords::save_data(&metadata_string, &data_file_name);
        model::Passwords::set_file_perms(&data_file_name, 0o600);
        return;
    }

    // Functionality that does require loading the key
    // get
    let key = common::load_or_create_key(&key_file_name);
    if let Some(ref matches) = matches.subcommand_matches("get") {
        let title = matches.value_of("title").unwrap();
        let password = old_data.find_by_title_or_bail(&title);
        let decoded_salt: Vec<u8> = password.salt
                                            .from_base64()
                                            .expect("Salt base64 decoding failed");
        let pass = common::generate_password(&key, decoded_salt, common::GENERATED_INPUT_LENGTH);

        println!("{}", common::cut_password(pass, password.format, password.length));
        return;
    }

}

