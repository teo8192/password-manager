use codes::crypt::chacha20::ChaCha20;
use codes::crypt::mac::HMAC;
use codes::crypt::pbkdf2;
use codes::crypt::Cipher;

use rusqlite::NO_PARAMS;
use rusqlite::{Connection, Result};

use structopt::StructOpt;

use openssl::rand::rand_bytes;

#[derive(StructOpt)]
#[structopt(name = "spm", about = "Simple Password Manager.")]
struct CliOpt {
    #[structopt(long)]
    pass0: String,
    #[structopt(long)]
    pass1: Option<String>,
    #[structopt(short, long)]
    name: String,
    #[structopt(long)]
    database: Option<String>,
}

#[derive(Debug)]
struct Row {
    name: String,
    salt: String,
    nonce: String,
    password: String,
}

pub fn to_hex(bytes: Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

pub fn from_hex(bytes: String) -> Vec<u8> {
    bytes
        .into_bytes()
        .chunks_mut(2)
        .map(|b| {
            u8::from_str_radix(std::str::from_utf8(b).expect("not utf8"), 16)
                .expect("could not convert from hex")
        })
        .collect()
}

fn main() -> Result<(), String> {
    let args = CliOpt::from_args();

    let mut conn = Connection::open(args.database.unwrap_or_else(|| "./passwords.db".to_owned()))
        .map_err(|e| e.to_string())?;

    conn.execute(
        "create table if not exists passwords (
            name text not null primary key,
            salt text not null unique,
            nonce text not null unique,
            password text not null unique
        )",
        NO_PARAMS,
    )
    .map_err(|e| e.to_string())?;

    let mut row: Vec<Row> = conn
        .prepare("SELECT * FROM passwords where name = (?1);")
        .map_err(|e| e.to_string())?
        .query_map(&[&args.name], |row| {
            Ok(Row {
                name: row.get(0)?,
                salt: row.get(1)?,
                nonce: row.get(2)?,
                password: row.get(3)?,
            })
        })
        .map_err(|e| e.to_string())?
        .filter_map(|x| match x {
            Ok(row) => Some(row),
            Err(_) => None,
        })
        .collect();

    let (salt, nonce, mut password, insert) = if row.is_empty() {
        if let Some(password) = args.pass1 {
            // generate random bytes
            let mut buf = [0; 256];
            rand_bytes(&mut buf).unwrap();
            let mut buf = buf.iter().copied();

            // take some random bytes to create salt and nonce
            let salt: Vec<u8> = (&mut buf).take(16).collect();
            let nonce: Vec<u8> = buf.take(8).collect();

            // convert the password from a string to a byte vector
            let password = password.into_bytes();

            (salt, nonce, password, true)
        } else {
            unimplemented!();
        }
    } else {
        // extract some stuff from the vector
        let row = if let Some(row) = row.pop() {
            row
        } else {
            panic!("this should not happen");
        };

        // convert the stuff from the database
        (
            from_hex(row.salt),
            from_hex(row.nonce),
            from_hex(row.password),
            false,
        )
    };

    // generate the key
    let key_vec = pbkdf2(args.pass0.as_ref(), &salt, 1 << 14, 256, &HMAC::default());

    // copy the key over to a known size
    let mut key = [0u8; 32];
    unsafe {
        std::ptr::copy(key_vec.as_ptr(), key.as_mut_ptr(), key_vec.len());
    }

    // encrypt/decrypt that mother fucker
    // it is the same operation for the ChaCha20 stream cipher
    let chacha = ChaCha20::new(&key);
    Cipher::encrypt(&chacha, &nonce, &mut password)?;

    if insert {
        // insert the generated values
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        // insert the stuff into the database
        tx.execute(
            "INSERT INTO passwords values (?1, ?2, ?3, ?4)",
            &[&args.name, &to_hex(salt), &to_hex(nonce), &to_hex(password)],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
    } else {
        // print the decrypted password
        println!(
            "{}",
            std::str::from_utf8(&password).map_err(|e| e.to_string())?
        );
    }

    Ok(())
}
