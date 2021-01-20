use structopt::StructOpt;

use std::process::Command;

use dialoguer::Password;

#[derive(StructOpt)]
#[structopt(name = "spm", about = "Simple Password Manager.")]
struct CliOpt {
    #[structopt(long)]
    pass0: Option<String>,
    #[structopt(long)]
    pass1: Option<String>,
    #[structopt(short, long)]
    name: Option<String>,
    #[structopt(long)]
    database: Option<String>,
    #[structopt(short, long)]
    generate: bool,
    #[structopt(short, long)]
    remove: bool,
    #[structopt(short, long)]
    list: bool,

    #[structopt(long)]
    pass_cmd: Option<String>,

    #[structopt(subcommand)]
    rest: Option<Subcommands>,
}

#[derive(StructOpt)]
enum Subcommands {
    #[structopt(external_subcommand)]
    Name(Vec<String>),
}

/// configuration for rw password
pub struct RwConfig<T: GetPassword> {
    /// encryption password
    pub encryption_password: Option<String>,
    /// password to be encrypted
    pub password: Option<String>,
    /// generate a password
    pub generate: bool,
    /// name of password
    pub name: String,
    /// length of generated password (default 16)
    pub genlen: usize,
    /// number of bytes in the pbkdf2 salt (default 16)
    pub nsaltbytes: usize,
    /// iteration count for pbkdf2 (default 1 << 14). Possible values (based on reccomendation from RFC8018), 1000 sould be suitable, 10,000,000 for critical applications where user-percieved performance is not critical
    pub iter_count: usize,

    pub get_password: T,
}

/// the config
pub struct Config<T: GetPassword> {
    /// name of password database
    pub database: String,
    /// list passwords
    pub list: bool,
    /// remove the selected password
    pub remove: bool,
    /// name of hte password
    pub name: String,
    /// RW config
    pub rw_config: Option<RwConfig<T>>,
}

pub trait GetPassword {
    fn get_password(&self, prompt: &str) -> Result<String, String>;
}

pub struct PasswordRunner {
    command: Option<String>,
}

impl GetPassword for PasswordRunner {
    fn get_password(&self, prompt: &str) -> Result<String, String> {
        if let Some(command) = &self.command {
            let command = format!("{} \"{}\" | tr -d '\n'", command, prompt);

            let output = Command::new("sh")
                .arg("-c")
                .arg(command)
                .output()
                .map_err(|e| e.to_string())?;

            std::str::from_utf8(&output.stdout)
                .map_err(|e| e.to_string())
                .map(|s| s.to_owned())
        } else {
            Password::new()
                .with_prompt(prompt)
                .interact()
                .map_err(|e| e.to_string())
        }
    }
}

pub fn parse_config() -> Result<Config<PasswordRunner>, String> {
    let args = CliOpt::from_args();

    let name = if args.remove || !args.list {
        if let Some(name) = args.name {
            Ok(name)
        } else {
            if let Some(Subcommands::Name(mut name)) = args.rest {
                if name.len() > 1 {
                    Err("Too many arguments".to_owned())
                } else {
                    name.pop().ok_or("Could not extract name".to_owned())
                }
            } else {
                Err("Missing name".to_owned())
            }
        }
    } else {
        Ok("".to_owned())
    }?;

    Ok(Config {
        database: args.database.unwrap_or_else(|| "./passwords.db".to_owned()),
        list: args.list,
        remove: args.remove,
        name: name.clone(),
        rw_config: if args.remove {
            None
        } else {
            Some(RwConfig {
                encryption_password: args.pass0,
                password: args.pass1,
                name,
                generate: args.generate,
                genlen: 16,
                nsaltbytes: 16,
                iter_count: 1 << 11,
                get_password: PasswordRunner {
                    command: args.pass_cmd,
                },
            })
        },
    })
}
