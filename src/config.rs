use structopt::StructOpt;

use std::process::Command;

use openssl::{base64, rand::rand_bytes};

use dialoguer::Password;

#[derive(StructOpt)]
#[structopt(name = "spm", about = "Simple Password Manager.")]
struct CliOpt {
    #[structopt(long)]
    /// The encryption password
    pass0: Option<String>,

    #[structopt(long)]
    /// The password to be encrypted
    pass1: Option<String>,

    #[structopt(short, long)]
    /// Name of the password
    name: Option<String>,

    #[structopt(long, default_value = "./passwords.db")]
    /// The name of the password database
    database: String,

    #[structopt(short, long)]
    /// Generate a random password
    generate: bool,

    #[structopt(short, long)]
    /// Remove the selected password
    remove: bool,

    #[structopt(short, long)]
    /// List all passwords in the database
    list: bool,

    #[structopt(long, default_value = "16", required_if("generate", "true"))]
    /// Length of the generated password
    generation_length: usize,

    #[structopt(long, default_value = "16")]
    /// number of salt bytes
    salt_bytes: usize,

    #[structopt(long)]
    /// Command to get a password, e.g. 'dmenu -P -p'.
    /// A prompt will be appended to the command.
    pass_cmd: Option<String>,

    #[structopt(subcommand)]
    /// Name
    rest: Option<Subcommand>,
}

#[derive(StructOpt)]
enum Subcommand {
    #[structopt(external_subcommand)]
    /// Name
    Name(Vec<String>),
}

/// configuration for rw password
pub struct RwConfig<T: GetPassword> {
    /// encryption password
    pub encryption_password: T,
    /// password to be encrypted
    pub password: T,
    /// name of password
    pub name: String,
    /// number of bytes in the pbkdf2 salt (default 16)
    pub nsaltbytes: usize,
    /// iteration count for pbkdf2 (default 1 << 14). Possible values (based on reccomendation from RFC8018), 1000 sould be suitable, 10,000,000 for critical applications where user-percieved performance is not critical
    pub iter_count: usize,
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

enum PasswordRunnerContent {
    Command(String),
    Password(String),
    Generate(usize),
    Prompt,
}

pub struct PasswordRunner {
    content: PasswordRunnerContent,
    confirm: bool,
}

impl PasswordRunner {
    fn new(
        password: Option<String>,
        command: Option<String>,
        confirm: bool,
        generate: bool,
        gen_len: usize,
    ) -> Self {
        use PasswordRunnerContent::*;
        Self {
            content: if generate {
                Generate(gen_len)
            } else if let Some(password) = password {
                Password(password)
            } else if let Some(command) = command {
                Command(command)
            } else {
                Prompt
            },
            confirm,
        }
    }
}

impl GetPassword for PasswordRunner {
    fn get_password(&self, prompt: &str) -> Result<String, String> {
        match &self.content {
            PasswordRunnerContent::Command(user_command) => {
                let output = Command::new("sh")
                    .arg("-c")
                    .arg(format!("{} \"{}\" | tr -d '\n'", user_command, prompt))
                    .output()
                    .map_err(|e| e.to_string())?;

                // confirm the password
                if self.confirm {
                    for (confirm_byte, orig_byte) in Command::new("sh")
                        .arg("-c")
                        .arg(format!("{} \"{}\" | tr -d '\n'", user_command, prompt))
                        .output()
                        .map_err(|e| e.to_string())?
                        .stdout
                        .iter()
                        .zip(output.stdout.iter())
                    {
                        if confirm_byte != orig_byte {
                            return Err("passwords does not match".to_string());
                        }
                    }
                }

                std::str::from_utf8(&output.stdout)
                    .map_err(|e| e.to_string())
                    .map(|s| s.to_owned())
            }
            PasswordRunnerContent::Password(password) => Ok(password.clone()),
            PasswordRunnerContent::Generate(len) => {
                let mut bytes = [0u8; 256];
                rand_bytes(&mut bytes).map_err(|e| e.to_string())?;

                let mut res = base64::encode_block(&bytes[..]);
                res.truncate(*len);

                Ok(res)
            }
            PasswordRunnerContent::Prompt => {
                if self.confirm {
                    Password::new()
                        .with_prompt(prompt)
                        .with_confirmation(
                            format!("Confirm {}", prompt),
                            "passwords does not match",
                        )
                        .interact()
                        .map_err(|e| e.to_string())
                } else {
                    Password::new()
                        .with_prompt(prompt)
                        .interact()
                        .map_err(|e| e.to_string())
                }
            }
        }
    }
}

pub fn parse_config() -> Result<Config<PasswordRunner>, String> {
    let args = CliOpt::from_args();

    let name = if args.remove || !args.list {
        if let Some(name) = args.name {
            Ok(name)
        } else {
            match args.rest {
                Some(Subcommand::Name(mut name)) => {
                    if name.len() > 1 {
                        Err("too many arguments".to_owned())
                    } else {
                        name.pop().ok_or_else(|| "missing name".to_owned())
                    }
                }
                _ => Err("missing name.".to_owned()),
            }
        }
    } else {
        Ok("".to_owned())
    }?;

    Ok(Config {
        database: args.database,
        list: args.list,
        remove: args.remove,
        name: name.clone(),
        rw_config: if args.remove {
            None
        } else {
            Some(RwConfig {
                encryption_password: PasswordRunner::new(
                    args.pass0,
                    args.pass_cmd.clone(),
                    false,
                    false,
                    0,
                ),
                password: PasswordRunner::new(
                    args.pass1,
                    args.pass_cmd,
                    true,
                    args.generate,
                    args.generation_length,
                ),
                name,
                nsaltbytes: args.salt_bytes,
                iter_count: 1 << 11,
            })
        },
    })
}
