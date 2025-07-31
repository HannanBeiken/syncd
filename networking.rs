use crate::{
    crypto::*,
    fsio::load_file,
    types::*,
};
use rand::Rng;
use std::str::FromStr;
use std::net::SocketAddr;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_native_tls::{native_tls, TlsStream};

type Stream = TlsStream<TcpStream>;

async fn 
authenticate(peer: &mut Stream, key_id: &String) -> Result<ResultTypes, ResultTypes> {
    let key_fpr = get_sign_key_fpr(&key_id)?;
    let mut buf = vec![];
    read_msg(peer, &mut buf).await?;
    let challenge = buf.clone();

    write_msg(peer, &key_id.as_bytes().to_vec()).await?;
    read_msg(peer, &mut buf).await?;
    match rt_from_bytes(&buf)? {
        ResultTypes::OK => (),
        ResultTypes::UnauthKey => return Err(ResultTypes::UnauthKey),
        _ => return Err(ResultTypes::UnknownErr),
    };

    let solution = sign_data(challenge, &key_fpr)?;
    write_msg(peer, &solution).await?;
    read_msg(peer, &mut buf).await?;
    match rt_from_bytes(&buf) {
        Ok(ResultTypes::OK) => return Ok(ResultTypes::OK),
        Err(ResultTypes::FprMismatch) => return Err(ResultTypes::FprMismatch),
        Err(ResultTypes::SigContentMismatch) => return Err(ResultTypes::SigContentMismatch),
        _ => return Err(ResultTypes::UnknownErr),
    }
}

async fn
authenticate_peer(stream: &mut Stream, authorized_keys: &Vec<String>) -> Result<ResultTypes, ResultTypes> {
    let mut buf = vec![];
    let challenge = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    write_msg(stream, &challenge).await?;

    read_msg(stream, &mut buf).await?;
    let peer_key_id = String::from_utf8(buf.clone())?;
    match verify_key_authorized(&authorized_keys, &peer_key_id) {
        Ok(o) => { write_msg(stream, &o.to_string().as_bytes().to_vec()).await?; },
        Err(e) => {
            write_msg(stream, &e.to_string().as_bytes().to_vec()).await?;
            return Err(e)
        }
    }
    let expected_key_fpr = get_sign_key_fpr(&peer_key_id)?;

    read_msg(stream, &mut buf).await?;
    let mut signed_data = vec![];
    match verify_signature(&buf, &expected_key_fpr, &mut signed_data) {
        Ok(_o) => {
            if signed_data != challenge { 
                write_msg(stream, &ResultTypes::SigContentMismatch.to_string().as_bytes().to_vec()).await?;
                return Err(ResultTypes::SigContentMismatch);
            }
            write_msg(stream, &ResultTypes::OK.to_string().as_bytes().to_vec()).await?;
            return Ok(ResultTypes::OK); 
        },
        Err(_e) => {
            write_msg(stream, &ResultTypes::FprMismatch.to_string().as_bytes().to_vec()).await?;
            return Err(ResultTypes::FprMismatch);
        }
    }
}

pub async fn 
bootstrap(peer_list: &Vec<String>, auth_conf: &AuthConf) -> Result<&'static str, &'static str> {
    for peer in peer_list {
        unsafe {
            let result = connect_to_peer(&peer, &auth_conf).await;
            match result {
                Ok(mut socket) => {
                    write_msg(&mut socket, &b"NewPeerLst".to_vec()).await;
                    return Ok("Successfully Bootstrapped");
                }
                Err(_error) => {
                    println!("Error Connecting To Peer {}", peer);
                }
            }
        }
    } 
    Err("Failed To Connect To A Peer")
}

pub async fn 
broadcast() {
    
}

pub async unsafe fn 
broadcast_listen(listen_address: String, tls_identity_path: String, 
                 tls_identity_password: String, key_id: String,
                 authorized_keys: Vec<String>) {

    let tls_identity = load_file(&tls_identity_path).await;
    let tls_identity = native_tls::Identity::from_pkcs12(&tls_identity.as_slice(), 
                                                         &tls_identity_password).unwrap();
    let tls_acceptor = tokio_native_tls::TlsAcceptor::from(native_tls::TlsAcceptor::new(tls_identity).unwrap());

    let tcp_listener = TcpListener::bind(listen_address).await.unwrap();
    loop {
        let (tcp_stream, _client) = tcp_listener.accept().await.unwrap(); //? ignorable error
        let mut tls_stream = tls_acceptor.accept(tcp_stream).await.unwrap(); //? if no error cont. else discard stream 
        let key_id = key_id.clone();
        let authorized_keys = authorized_keys.clone();
        tokio::spawn(async move {
            authenticate(&mut tls_stream, &key_id).await.expect("Authenticate Error");
            authenticate_peer(&mut tls_stream, &authorized_keys).await.expect("Authenticate Peer Error");
            handle_client(tls_stream).await;
        });
    }
}

pub async unsafe fn 
connect_to_peer(peer_addr: &str, auth_conf: &AuthConf) -> Result<Stream, ResultTypes> {
    let tls_connector = native_tls::TlsConnector::builder()
        .danger_accept_invalid_certs(true)
        .build()?;
    let tls_connector = tokio_native_tls::TlsConnector::from(tls_connector);

    let tcp_stream = TcpStream::connect(peer_addr).await?;
    let socket_addr = SocketAddr::from_str(peer_addr)?;
    let socket_addr = socket_addr.ip().to_string();
    let mut tls_stream = tls_connector.connect(&socket_addr, tcp_stream).await?;
    authenticate_peer(&mut tls_stream, &auth_conf.authorized_keys).await?;
    authenticate(&mut tls_stream, &auth_conf.key_id).await?;
    Ok(tls_stream)
}

async fn 
handle_client(mut peer: Stream) {
    loop {
        let mut msg = vec![];
        read_msg(&mut peer, &mut msg).await;
        match String::from_utf8(msg.clone()).unwrap().as_str() {
            "NewPeerLst" => panic!("Yes"),
            _ => (),
        }
    }
}

async fn
read_msg(stream: &mut Stream, buf: &mut Vec<u8>) -> Result<ResultTypes, ResultTypes> {
    let mut msg_len: [u8; 8] = [0, 0, 0, 0, 0, 0, 0, 0]; 
    stream.read_exact(&mut msg_len).await?; //Read Len of Msg
    let msg_len = usize::from_ne_bytes(msg_len);

    let mut msg = vec![0u8; msg_len];
    stream.read_exact(&mut msg).await?;
    buf.clear();
    for byte in msg {
        buf.push(byte);
    }
    Ok(ResultTypes::OK) 
}

async fn
write_msg(stream: &mut Stream, msg: &Vec<u8>) -> Result<ResultTypes, ResultTypes> {
    let msg_len: [u8; 8] = msg.len().to_ne_bytes();
    stream.write_all(&msg_len).await?;
    stream.write_all(msg).await?;
    Ok(ResultTypes::OK)
}
