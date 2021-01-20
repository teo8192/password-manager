use codes::crypt::chacha20::ChaCha20;
use codes::crypt::mac::HMAC;
use codes::crypt::{pbkdf2, Cipher};

use openssl::rand::rand_bytes;

use crate::config::{GetPassword, RwConfig};

#[derive(Debug)]
pub struct Row {
    pub name: String,
    pub salt: String,
    pub nonce: String,
    pub password: String,
}

pub struct Password {
    password: Vec<u8>,
}

impl From<Vec<u8>> for Password {
    fn from(bytes: Vec<u8>) -> Self {
        Self { password: bytes }
    }
}

impl From<Password> for String {
    fn from(password: Password) -> Self {
        to_hex(password.password)
    }
}

impl std::fmt::Display for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}",
            unpad_password(self.password.clone()).map_err(|_| std::fmt::Error)?
        )
    }
}

/// convert from a vector of bytes to a hex string
fn to_hex(bytes: Vec<u8>) -> String {
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

/// Convert from a hex string to a vector of bytes
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

/// Add padding to the password.
///
/// The first four bytes is an integer in a little endian order determining the number of padding
/// bytes. The value of the padding bytes are undefined, possibly 0
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

/// Remove the padding from the password.
///
/// The first four bytes is an integer in a little endian order determining the number of padding
/// bytes. The value of the padding bytes are undefined, possibly 0
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

/// Process the query result
pub fn process<T: GetPassword>(
    mut row: Vec<Row>,
    args: &RwConfig<T>,
) -> Result<(String, String, Password, bool), String> {
    let (salt, nonce, mut password, insert) = if let Some(row) = row.pop() {
        // convert the stuff from the database
        (
            from_hex(row.salt),
            from_hex(row.nonce),
            from_hex(row.password),
            false,
        )
    } else {
        // generate random bytes
        let mut buf = [0; 256];
        rand_bytes(&mut buf).unwrap();
        let mut buf = buf.iter().copied();

        // take some random bytes to create salt and nonce
        let salt: Vec<u8> = (&mut buf).take(args.nsaltbytes).collect();
        let nonce: Vec<u8> = buf.take(8).collect();

        let password = pad_password(args.password.get_password("New password")?)?;

        (salt, nonce, password, true)
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

    Ok((to_hex(salt), to_hex(nonce), Password::from(password), insert))
}
