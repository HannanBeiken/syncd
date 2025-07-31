mod crypto;
mod types;
mod fsio;
mod networking;

use fsio::*;
use networking::*;
use types::AuthConf;

#[tokio::main]
async fn main() {
    let config = load_config().expect("Failed To Read Config");
    let auth_conf = AuthConf {
        key_id: config.auth_key_id.clone(), 
        authorized_keys: config.authorized_keys.clone(),
    };
    gpgme::init();

    bootstrap(&config.peer_list, &auth_conf).await.expect("Failed To Bootstrap To Network");

    let config = config.clone();
    unsafe {
        tokio::spawn(async move {
            broadcast_listen(config.listen_address, config.tls_identity_path, 
                             String::from("password"), config.auth_key_id, config.authorized_keys).await;
        }).await;
    }
}
