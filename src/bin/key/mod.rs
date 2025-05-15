use std::{
    fs::{self, File},
    io::{self, Write},
    path::{Path, PathBuf},
};

use clap::{Parser, Subcommand};
use tracing::info;

#[derive(Parser)]
pub struct KeyCommand {
    #[command(subcommand)]
    action: KeyActions,
}

#[derive(Subcommand)]
enum KeyActions {
    /// Generate a new secp256k1 key
    Generate {
        /// Output file path for the key
        #[arg(short, long, required = false)]
        file: Option<PathBuf>,
    },
}

pub fn read_secp256k1_key_from_file<P: AsRef<Path>>(
    path: P,
) -> eyre::Result<enr::CombinedKey, std::io::Error> {
    let hex_content = fs::read_to_string(&path)?;
    let hex_clean = hex_content.trim().replace("0x", "").replace(" ", "");

    let mut bytes = hex::decode(&hex_clean).map_err(|e| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Invalid hex encoding: {}", e),
        )
    })?;

    let result = enr::CombinedKey::secp256k1_from_bytes(&mut bytes)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()));

    result
}

pub fn write_secp256k1_key_to_file<P: AsRef<Path>>(
    path: P,
    key: &enr::CombinedKey,
) -> eyre::Result<(), std::io::Error> {
    let hex_string = match &key {
        enr::CombinedKey::Secp256k1(secret_key) => hex::encode(secret_key.to_bytes()),
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "Expected Secp256k1 key but got a different type",
            ));
        }
    };

    let mut file = File::create(&path)?;
    file.write_all(hex_string.as_bytes())?;

    info!(
        "Secp256k1 key written to file in hex format: {}",
        path.as_ref().display()
    );

    Ok(())
}

pub fn run(key_cmd: KeyCommand) -> eyre::Result<()> {
    match key_cmd.action {
        KeyActions::Generate { file } => {
            info!("Generating new secp256k1 key");
            let key = enr::CombinedKey::generate_secp256k1();
            let hex_key = match &key {
                enr::CombinedKey::Secp256k1(sk) => hex::encode(sk.to_bytes()),
                _ => unreachable!("We generated a secp256k1 key"),
            };

            if let Some(path) = file {
                info!("Saving in raw format to {}", path.display());
                write_secp256k1_key_to_file(path, &key)?;
                info!("Key saved successfully");
            } else {
                println!("{}", hex_key);
            }
        }
    }
    Ok(())
}
