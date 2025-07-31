use crate::types::ResultTypes;
use serde_derive::Deserialize;
use tokio::{
    fs::File,
    io::{
        AsyncBufReadExt,
        AsyncReadExt,
        BufReader,
    },
};

#[derive(Deserialize)]
pub struct Config {
    pub auth_key_id: String,
    pub authorized_keys: Vec<String>,
    pub listen_address: String,
    pub peer_list: Vec<String>,
    pub tls_identity_path: String,
}

impl Clone for Config {
    fn clone(&self) -> Config {
        Config {
            auth_key_id: self.auth_key_id.clone(),
            authorized_keys: self.authorized_keys.clone(),
            listen_address: self.listen_address.clone(),
            peer_list: self.peer_list.clone(),
            tls_identity_path: self.tls_identity_path.clone(),
        }
    }
}

pub async fn read_lines(file_path: String) -> Vec<String> {
    let mut contents: Vec<String> = Vec::new();
    let file = File::open(file_path).await.unwrap();
    let mut reader = BufReader::new(file).lines();
    while let Some(line) = reader.next_line().await.unwrap() {
        contents.push(line);
    }
    return contents;
}

pub fn load_config() -> Result<Config, ResultTypes> {
    let config_toml = std::fs::read_to_string("config.toml")?;
    let config: Config = toml::from_str(&config_toml)?;
    Ok(config)
}

pub async fn load_file(path: &str) -> Vec<u8> {
    let mut file = File::open(path).await.expect("Failed To Open File");
    let mut contents = vec![];
    let _ = file.read_to_end(&mut contents).await;
    return contents;
}
