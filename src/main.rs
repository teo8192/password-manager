use codes::crypt::chacha20::ChaCha20;
use codes::crypt::mac::HMAC;
use codes::crypt::{pbkdf2, Cipher};

use rusqlite::{Connection, Result, NO_PARAMS};

use openssl::rand::rand_bytes;

mod config;

use config::{parse_config, GetPassword, RwConfig};

#[derive(Debug)]
struct Row {
    name: String,
    salt: String,
    nonce: String,
    password: String,
}

fn to_hex(bytes: Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn from_hex(bytes: String) -> Vec<u8> {
    bytes
        .into_bytes()
        .chunks_mut(2)
        .map(|b| {
            u8::from_str_radix(std::str::from_utf8(b).expect("not utf8"), 16)
                .expect("could not convert from hex")
        })
        .collect()
}

fn pad_password(password: String) -> Result<Vec<u8>, String> {
    let password = password.into_bytes();
    let length = password.len();

    let max_length = 128 - 4;

    if length >= max_length {
        return Err(format!("Password too long! (max size: {})", max_length));
    }
    let padding = max_length - length;
    Ok((length as u32)
        .to_le_bytes()
        .iter()
        .cloned()
        .chain(password.iter().cloned())
        .chain(std::iter::repeat(0).take(padding))
        .collect())
}

fn unpad_password(password: Vec<u8>) -> Result<String, String> {
    let mut iterator = password.iter();

    let mut bytes = [0u8; 4];
    for (inp, res) in (&mut iterator).take(4).zip(bytes.iter_mut()) {
        *res = *inp;
    }

    let length = u32::from_le_bytes(bytes);
    match std::str::from_utf8(&iterator.take(length as usize).cloned().collect::<Vec<u8>>()) {
        Err(e) => Err(e.to_string()),
        Ok(s) => Ok(s.to_owned()),
    }
}

fn rw_password<T: GetPassword>(args: &RwConfig<T>, conn: &mut Connection) -> Result<(), String> {
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

    let (salt, nonce, mut password, insert): (Vec<u8>, Vec<u8>, Vec<u8>, bool) = if row.is_empty() {
        // generate random bytes
        let mut buf = [0; 256];
        rand_bytes(&mut buf).unwrap();
        let mut buf = buf.iter().copied();

        // take some random bytes to create salt and nonce
        let salt: Vec<u8> = (&mut buf).take(args.nsaltbytes).collect();
        let nonce: Vec<u8> = buf.take(8).collect();

        let password = pad_password(args.password.get_password("New password")?)?;

        (salt, nonce, password, true)
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

    let encrypt_pass = args
        .encryption_password
        .get_password("Encryption password")?;

    // generate the key
    let key_vec = pbkdf2(
        encrypt_pass.as_ref(),
        &salt,
        args.iter_count,
        256,
        &HMAC::default(),
    );

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
        println!("{}", unpad_password(password)?);
    }

    Ok(())
}

fn main() -> Result<(), String> {
    let config = parse_config()?;

    let mut conn = Connection::open(&config.database).map_err(|e| e.to_string())?;

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

    if !config.remove && !config.list {
        rw_password(&config.rw_config.unwrap(), &mut conn)?;
    }

    if config.remove {
        // insert the generated values
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        // insert the stuff into the database
        tx.execute("DELETE FROM passwords WHERE name = (?1)", &[&config.name])
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
    }

    if config.list {
        #[derive(Debug)]
        struct R {
            name: String,
        }

        for name in conn
            .prepare("SELECT name FROM passwords;")
            .map_err(|e| e.to_string())?
            .query_map(NO_PARAMS, |row| Ok(R { name: row.get(0)? }))
            .map_err(|e| e.to_string())?
        {
            println!("{}", name.map_err(|e| e.to_string())?.name);
        }
    }

    Ok(())
}
