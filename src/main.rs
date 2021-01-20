use rusqlite::{Connection, Result, NO_PARAMS};

mod config;
mod password;

use config::parse_config;

use password::{process, Row};

fn main() -> Result<(), String> {
    let config = parse_config()?;

    // initialize database
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

    // either insert or look up a password
    if !config.remove && !config.list {
        // query the database and process the results
        let (salt, nonce, password, insert) = process(
            conn.prepare("SELECT * FROM passwords where name = (?1);")
                .map_err(|e| e.to_string())?
                .query_map(&[&config.name], |row| {
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
                .collect(),
            &config
                .rw_config
                .ok_or_else(|| "found not rw config".to_owned())?,
        )?;

        if insert {
            // insert the generated values
            let tx = conn.transaction().map_err(|e| e.to_string())?;
            // insert the stuff into the database
            tx.execute(
                "INSERT INTO passwords values (?1, ?2, ?3, ?4)",
                &[&config.name, &salt, &nonce, &String::from(password)],
            )
            .map_err(|e| e.to_string())?;
            tx.commit().map_err(|e| e.to_string())?;
        } else {
            // print the decrypted password
            println!("{}", password);
        }
    }

    // if to remove something from the database
    if config.remove {
        // insert the generated values
        let tx = conn.transaction().map_err(|e| e.to_string())?;
        // insert the stuff into the database
        tx.execute("DELETE FROM passwords WHERE name = (?1)", &[&config.name])
            .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())?;
    }

    // if listing
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
