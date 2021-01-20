use rusqlite::{Connection, Result, NO_PARAMS};

mod config;
mod password;

use config::parse_config;

use password::rw_password;

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
