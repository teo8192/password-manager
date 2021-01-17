use structopt::StructOpt;

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
}

/// configuration for rw password
pub struct RwConfig {
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
    /// iteration count for pbkdf2 (default 1 << 14). Possible values (based on reccomendation from RFC8018), 1000 sould be suitable, 10,000,000 for critical applications where user response is not critical.
    pub iter_count: usize,
}

/// the config
pub struct Config {
    /// name of password database
    pub database: String,
    /// list passwords
    pub list: bool,
    /// remove the selected password
    pub remove: bool,
    /// name of hte password
    pub name: String,
    /// RW config
    pub rw_config: Option<RwConfig>,
}

pub fn parse_config() -> Result<Config, String> {
    let args = CliOpt::from_args();

    let name = if args.remove || !args.list {
        args.name.ok_or("Missing name".to_owned())
    } else {
        Ok("".to_owned())
    }?;

    Ok(Config {
        database: args.database.unwrap_or_else(|| "./password.db".to_owned()),
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
                iter_count: 1 << 14,
            })
        },
    })
}
