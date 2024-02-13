mod auth;

use anyhow::Context;
use auth::{login, signup};
use bfsp::ipc;
use bfsp::Message;
use bfsp::PrependLen;
use bfsp::{config::write_to_config, crypto::EncryptionKey};
use clap::{command, Parser};
use futures::AsyncReadExt;
use futures::AsyncWriteExt;
use interprocess::local_socket::{tokio::LocalSocketStream, NameTypeSupport};
use path_absolutize::Absolutize;
use std::path::PathBuf;
use thiserror::Error;
use tokio::fs;
use tokio::process;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
pub struct Args {
    #[command(subcommand)]
    command: Command,
}

#[derive(Parser, Debug, Clone)]
enum Command {
    Login { email: String, password: String },
    Signup { email: String, password: String },
    AddDirectory { path: PathBuf },
    ListDirectory { path: PathBuf },
    RemoveDirectory { path: PathBuf },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let command = Command::parse();

    let config_path = bfsp::config::get_config_dir().await?.join("config.toml");
    let mut config = bfsp::config::config_from_file(&config_path).await?;

    let macaroon = if let Some(macaroon) = config.macaroon.clone() {
        macaroon
    } else {
        let macaroon = match &command {
            Command::Login { email, password } => login(email.clone(), password.clone()).await?,
            Command::Signup { email, password } => {
                signup(email.clone(), password.clone()).await?;
                println!("Successfully signed up. Please login.");
                return Ok(());
            }
            _ => {
                println!("Please login first");
                return Ok(());
            }
        };

        config.macaroon = Some(macaroon.clone());
        write_to_config(&config_path, &config).await?;

        macaroon
    };

    let enc_key = if let Some(enc_key) = config.enc_key {
        EncryptionKey::try_from(hex::decode(enc_key)?)?
    } else {
        let key = EncryptionKey::new();
        let key_bytes: Vec<u8> = key.clone().into();
        config.enc_key = Some(hex::encode(key_bytes));
        write_to_config(&config_path, &config).await?;

        key
    };

    let interprocess_path = {
        match NameTypeSupport::query() {
            NameTypeSupport::OnlyPaths => "/tmp/befsd.sock",
            NameTypeSupport::OnlyNamespaced | NameTypeSupport::Both => "@befsd.sock",
        }
    };

    match command {
        Command::Login {
            email: _,
            password: _,
        }
        | Command::Signup {
            email: _,
            password: _,
        } => (),
        Command::AddDirectory { path } => {
            let path = path.absolutize().unwrap();

            let msg = ipc::IpcMessage {
                message: Some(ipc::ipc_message::Message::AddDirectory(
                    ipc::ipc_message::AddDirectory {
                        directory: path.to_str().unwrap().to_string(),
                    },
                )),
            };

            let mut ipc_stream = LocalSocketStream::connect(interprocess_path).await?;
            ipc_stream
                .write_all(&msg.encode_to_vec().prepend_len())
                .await
                .with_context(|| "error sending AddDirectory message to bfsd")?;
        }
        Command::ListDirectory { path } => {
            let path = path.absolutize().unwrap();

            let msg = ipc::IpcMessage {
                message: Some(ipc::ipc_message::Message::ListDirectory(
                    ipc::ipc_message::ListDirectory {
                        directory: path.to_str().unwrap().to_string(),
                    },
                )),
            };

            let mut ipc_stream = LocalSocketStream::connect(interprocess_path).await?;
            ipc_stream
                .write_all(&msg.encode_to_vec().prepend_len())
                .await
                .with_context(|| "error sending ListDirectory message to bfsd")?;

            let mut len = [0u8; 4];
            ipc_stream
                .read_exact(&mut len)
                .await
                .with_context(|| "error reading bfsd message len")?;
            let len: u32 = u32::from_le_bytes(len);

            let mut buf = vec![0; len as usize];
            ipc_stream
                .read_exact(&mut buf)
                .await
                .with_context(|| "error reading from bfsd")?;

            let listing = ipc::DirectoryListing::decode(buf.as_slice())
                .with_context(|| "error decoding ListDirectoryResponse")?;
            for entry in listing.file.iter() {
                println!("{}", entry.path);
            }
        }
        Command::RemoveDirectory { path } => {
            let path = path.absolutize().unwrap();

            let msg = ipc::IpcMessage {
                message: Some(ipc::ipc_message::Message::RemoveDirectory(
                    ipc::ipc_message::RemoveDirectory {
                        directory: path.to_str().unwrap().to_string(),
                    },
                )),
            };

            let mut ipc_stream = LocalSocketStream::connect(interprocess_path).await?;
            ipc_stream
                .write_all(&msg.encode_to_vec().prepend_len())
                .await
                .with_context(|| "error sending ListDirectory message to bfsd")?;


        }
    }

    //start_befsd().await?;

    Ok(())
}

#[derive(Error, Debug)]
enum StartBEFSDError {
    #[error("executable directory not found")]
    NoExecutableDir,
    #[error("Couldn't start befsd")]
    StartBFSDFailure(#[from] std::io::Error),
}

async fn start_befsd() -> Result<(), StartBEFSDError> {
    let bfsd_path: PathBuf = {
        if let Some(env) = std::env::var_os("BEFSD_PATH") {
            env.into()
        } else if cfg!(target_os = "linux") {
            "/usr/bin/befsd".into()
        } else if cfg!(target_os = "macos") {
            "/usr/local/bin/befsd".into()
        } else if cfg!(target_os = "windows") {
            "C:\\Program Files\\bfsd\\befsd.exe".into()
        } else {
            panic!("Unsupported OS")
        }
    };
    println!("Starting befsd at {}", bfsd_path.display());

    process::Command::new(bfsd_path).spawn()?;
    Ok(())
}
