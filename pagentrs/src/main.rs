use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::kernel_providers::KernelProvider;
use ferrisetw::{provider::*, schema_locator, GUID};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use ferrisetw::EventRecord;
use serde::{Deserialize, Serialize};
use tokio::net::tcp;
use windows::Win32::System::Diagnostics::Etw;
use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::collections::HashMap;
use std::env::Args;
use std::fs::File;
use std::future::{Future, IntoFuture};
use std::hash::Hash;
use std::io::{self, Error, Write};
use std::net::{AddrParseError, IpAddr, Ipv4Addr, SocketAddrV4, TcpStream};
use std::path::{Path, PathBuf};
use std::process::exit;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;


pub const EVENT_TRACE_FLAG_FILE_IO: u32 = 0x02000000;
pub const EVENT_TRACE_FLAG_FILE_IO_INIT: u32 = 0x04000000;
pub const EVENT_TRACE_FLAG_DISK_FILE_IO: u32 = 0x00000200;

//https://learn.microsoft.com/en-us/windows/win32/etw/fileio
pub const FILEIO_NAME_NAME:u8 = 0;
pub const FILEIO_NAME_CREATE:u8 = 32;
pub const FILEIO_NAME_DELETE:u8 = 35;
pub const FILEIO_NAME_RUNDOWN:u8 = 36;

pub const FILEIO_CREATE:u8 = 64;

pub const FILEIO_RW_READ:u8 = 67;
pub const FILEIO_RW_WRITE:u8 = 68;

pub const FILEIO_SIMPLEOP_CLEANUP:u8 = 65;
pub const FILEIO_SIMPLEOP_CLOSE:u8 = 66;
pub const FILEIO_SIMPLEOP_FLUSH:u8 = 73;

pub const FILEIO_INFO_SET:u8 = 69;
pub const FILEIO_INFO_DELETE:u8 = 70;
pub const FILEIO_INFO_RENAME:u8 = 71;
pub const FILEIO_INFO_QUERY:u8 = 74;
pub const FILEIO_INFO_CONTROL:u8 = 75;

pub const FILEIO_OPEND:u8 = 76;

trait Repr {
    fn to_string(&self) -> String;
}

#[derive(Debug)]
struct MyPointer(Pointer);

impl Serialize for MyPointer {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where
            S: serde::Serializer {
        //println!("alo?");
        serializer.serialize_newtype_struct("Pointer", &self.0.clone().to_string())
    }
}

impl From<Pointer> for MyPointer {
    fn from(value: Pointer) -> Self {
        Self(value)
    }
}


#[derive(Debug, Serialize)]
struct FileName{
    file_name:String,
    file_object:u64,
}

impl FileName {
    fn new(parser: &Parser) -> Self{
        let file_name:String = parser.try_parse("FileName").unwrap_or(String::from("Err parsing FileName"));
        let file_object:u64 = parser.try_parse("FileObject").unwrap_or(0);  
        return FileName{file_name, file_object}                  
    }
}
impl Repr for FileName {
    fn to_string(&self) -> String {
        return format!("\"file_name\":\"{}\",\"file_object\":{}", self.file_name, self.file_object);
    }
}

//https://serde.rs/remote-derive.html
//cant use serde serialize on structs with ferrisetw::Pointer because they forgot? to derive it in their lib
#[derive(Debug, Serialize)]
struct FileCreate{
    irpptr:MyPointer,
    ttid:MyPointer,
    file_object:MyPointer,
    create_options:u32,
    file_attributes:u32,
    share_access:u32,
    open_path:String
}
impl FileCreate {
    fn new(parser: &Parser) ->Self{
        let irpptr:Pointer = parser.try_parse("IrpPtr").unwrap_or_default();
        let ttid:Pointer = parser.try_parse("TTID").unwrap_or_default();
        let file_object:Pointer = parser.try_parse("FileObject").unwrap_or_default();
        let create_options:u32 = parser.try_parse("CreateOptions").unwrap_or(0);
        let file_attributes:u32 = parser.try_parse("FileAttributes").unwrap_or(0);
        let share_access:u32 = parser.try_parse("ShareAccess").unwrap_or(0);
        let open_path:String = parser.try_parse("OpenPath").unwrap_or(String::from("Couldn't parse OpenPath"));                    
        FileCreate{irpptr: MyPointer(irpptr),ttid: MyPointer(ttid),file_object: MyPointer(file_object),create_options,file_attributes,share_access,open_path}
    }
}
// impl Repr for FileCreate {
//     fn to_string(&self) -> String {
//         return format!("\"irpptr\":{},\"ttid\":{},\"file_object\":{},\"create_options\":{},\"file_attributes\":{},\"share_access\":{},\"open_path\":\"{}\"", self.irpptr, self.ttid, self.file_object, self.create_options, self.file_attributes, self.share_access, self.open_path);
//     }
// }

#[derive(Debug, Serialize)]
struct FileReadWrite{
    file_key:u64,
    file_object:u64,
    iosize:u32,
    offset:u64,
    file_name:Option<String>
}

impl FileReadWrite {
    fn new(parser: &Parser) -> Self{
        let file_key:u64 = parser.try_parse("FileKey").unwrap_or(0);
        let file_object:u64 = parser.try_parse("FileObject").unwrap_or(0);
        let iosize:u32 = parser.try_parse("IoSize").unwrap_or(0);
        let offset:u64 = parser.try_parse("Offset").unwrap_or(0);
        FileReadWrite{file_key, file_object, iosize, offset, file_name:None}
    }

    fn set_filename(&mut self, name:&str){
        self.file_name = Some(name.to_string());
    }
}
// impl Repr for FileReadWrite {
//     fn to_string(&self) -> String {
//         return format!("\"file_key\":{},\"file_object\":{},\"iosize\":{},\"offset\":{}", self.file_key, self.file_object, self.iosize, self.offset);
//     }
// }


#[derive(Debug, Serialize)]
struct FileSimpleOp {
    irpptr:MyPointer,
    ttid:MyPointer, 
    file_object:MyPointer,
    file_key:u64 
}
impl FileSimpleOp {
    fn new(parser: &Parser) -> Self {
        let irpptr:Pointer = parser.try_parse("IrpPtr").unwrap_or_default();
        let ttid:Pointer = parser.try_parse("TTID").unwrap_or_default();
        let file_object:Pointer = parser.try_parse("FileObject").unwrap_or_default();
        let file_key:u64 = parser.try_parse("FileKey").unwrap_or(0);
        FileSimpleOp{irpptr: MyPointer(irpptr), ttid: MyPointer(ttid), file_object: MyPointer(file_object), file_key}
    }
}
// impl Repr for FileSimpleOp {
//     fn to_string(&self) -> String {
//         return format!("\"irpptr\":{},\"ttid\":{},\"file_object\":{},\"file_key\":{}", self.irpptr, self.ttid, self.file_object, self.file_key);
//     }
// }

#[derive(Debug, Serialize)]            
struct FileInfo{
    irpptr:MyPointer,
    ttid:MyPointer,
    file_object:MyPointer,
    file_key:u64,
    extra_info:MyPointer,
    info_class:u32
}
impl FileInfo {
    fn new(parser: &Parser) ->Self {
        let irpptr:Pointer = parser.try_parse("IrpPtr").unwrap_or_default();
        let ttid:Pointer = parser.try_parse("TTID").unwrap_or_default();
        let file_object:Pointer = parser.try_parse("FileObject").unwrap_or_default();
        let file_key:u64 = parser.try_parse("FileKey").unwrap_or(0);
        let extra_info:Pointer = parser.try_parse("ExtraInfo").unwrap_or_default();
        let info_class:u32 = parser.try_parse("InfoClass").unwrap_or(0);
        FileInfo{irpptr: MyPointer(irpptr), ttid: MyPointer(ttid), file_object: MyPointer(file_object),file_key, extra_info: MyPointer(extra_info), info_class}
    }
}
// impl Repr for FileInfo {
//     fn to_string(&self) -> String {
//         return format!("\"irpptr\":{},\"ttid\":{},\"file_object\":{},\"file_key\":{},\"extra_info\":{},\"info_class\":{}", self.irpptr, self.ttid, self.file_object, self.file_key, self.extra_info, self.info_class);
//     }
// }

#[derive(Debug, Serialize)]
struct FileEndOp{
    irpptr:MyPointer,
    extra_info:MyPointer,
    nt_status:u32
}
impl FileEndOp {
    fn new(parser:&Parser) -> Self{
        let irpptr:Pointer = parser.try_parse("IrpPtr").unwrap_or_default();
        let extra_info:Pointer = parser.try_parse("ExtraInfo").unwrap_or_default();
        let nt_status:u32 = parser.try_parse("NtStatus").unwrap_or(0);
        FileEndOp{irpptr: MyPointer(irpptr), extra_info: MyPointer(extra_info), nt_status}
    }
}
// impl Repr for FileEndOp {
//     fn to_string(&self) -> String {
//         return format!("\"irpptr\":{},\"extra_info\":{},\"nt_status\":{}", self.irpptr, self.extra_info, self.nt_status);
//     }
// }

fn fileio_callback(record: &EventRecord, schema_locator: &SchemaLocator, file_objects_record: &Mutex<HashMap<u64,String>>, stream: &Mutex<TcpStream>) {
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            let parser = Parser::create(record, &schema);
            //println!("[-] {} - {} - {} - {} - {} - {} - {} - {}",schema.provider_name(), schema.task_name(), schema.opcode_name(), record.event_flags(), record.opcode(), record.process_id(), record.thread_id() , record.raw_timestamp());
            match record.opcode() {
                FILEIO_NAME_NAME|
                FILEIO_NAME_CREATE|
                FILEIO_NAME_DELETE|
                FILEIO_NAME_RUNDOWN => {//name
                    let event = FileName::new(&parser);
                    file_objects_record.lock().map(|mut x|{x.insert(event.file_object.clone(), event.file_name.clone())});
                    match stream.lock() {
                        Ok(mut tcp_stream) => {
                            tcp_stream.write_all(serde_json::to_string(&event).unwrap_or("Failed parsing FILEIO_NAME to json".to_string()).as_bytes())
                            .or_else(|e|{
                                println!("Failed writing to tcp stream with: {}", e);
                                Err(e)
                            });
                        },
                        Err(e) => {
                            println!("Failed acquiring tcp lock with: {}", e);
                        }
                    }
                    //stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"Name\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());
                },
                FILEIO_CREATE => {//create
                    let event = FileCreate::new(&parser);
                    match stream.lock() {
                        Ok(mut tcp_stream) => {
                            tcp_stream.write_all(serde_json::to_string(&event).unwrap_or("Failed parsing FILEIO_CREATE to json".to_string()).as_bytes()).or_else(|e|{
                                println!("Failed writing to tcp stream with: {}", e);
                                Err(e)
                            });
                        },
                        Err(e) => {
                            println!("Failed acquiring tcp lock with: {}", e);
                        }
                    }
                    //stream.lock().map(|mut x|{x.write_all(serde_json::to_string(&event).unwrap_or("Failed parsing FILEIO_CREATE to json".to_string()).as_bytes())});
                    //stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"Create\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());
                },
                FILEIO_RW_READ|
                FILEIO_RW_WRITE => {//readwrite
                    let nf = String::from("Not found");
                    let mut event = FileReadWrite::new(&parser);
                    let file_name;
                    {
                        let map_guard = file_objects_record.lock().unwrap();
                        file_name = map_guard.get(&event.file_key).unwrap_or(&nf).clone();
                    }
                    event.set_filename(&file_name);
                    match stream.lock() {
                        Ok(mut tcp_stream) => {
                            tcp_stream.write_all(serde_json::to_string(&event).unwrap_or("Failed parsing FILEIO_RW to json".to_string()).as_bytes()).or_else(|e|{
                                println!("Failed writing to tcp stream with: {}", e);
                                Err(e)
                            });
                        },
                        Err(e) => {
                            println!("Failed acquiring tcp lock with: {}", e);
                        }
                    }
                    println!("{}", serde_json::to_string(&event).unwrap_or("Failed parsing FILEIO_RW to json".to_string()))
                    //stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"ReadWrite\", {}, \"file_name\":\"{}\"}}\n",record.process_id(), schema.opcode_name(), &event.to_string(), &file_name)).as_bytes());
                },
                FILEIO_SIMPLEOP_CLEANUP|
                FILEIO_SIMPLEOP_CLOSE|
                FILEIO_SIMPLEOP_FLUSH => {//simpleop
                    let event = FileSimpleOp::new(&parser);
                    match stream.lock() {
                        Ok(mut tcp_stream) => {
                            tcp_stream.write_all(serde_json::to_string(&event).unwrap_or("Failed parsing FILEIO_SIMPLEOP to json".to_string()).as_bytes()).or_else(|e|{
                                println!("Failed writing to tcp stream with: {}", e);
                                Err(e)
                            });
                        },
                        Err(e) => {
                            println!("Failed acquiring tcp lock with: {}", e);
                        }
                    }
                    //stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"SimpleOp\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());
                },
                FILEIO_INFO_SET|
                FILEIO_INFO_DELETE|
                FILEIO_INFO_RENAME|
                FILEIO_INFO_QUERY|
                FILEIO_INFO_CONTROL => {//info
                    let event = FileInfo::new(&parser);
                    match stream.lock() {
                        Ok(mut tcp_stream) => {
                            tcp_stream.write_all(serde_json::to_string(&event).unwrap_or("Failed parsing FILEIO_INFO to json".to_string()).as_bytes()).or_else(|e|{
                                println!("Failed writing to tcp stream with: {}", e);
                                Err(e)
                            });
                        },
                        Err(e) => {
                            println!("Failed acquiring tcp lock with: {}", e);
                        }
                    }
                    //stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"Info\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());
                },
                FILEIO_OPEND => {//opEnd
                    let event = FileEndOp::new(&parser);
                    match stream.lock() {
                        Ok(mut tcp_stream) => {
                            tcp_stream.write_all(serde_json::to_string(&event).unwrap_or("Failed parsing FILEIO_OPEND to json".to_string()).as_bytes()).or_else(|e|{
                                println!("Failed writing to tcp stream with: {}", e);
                                Err(e)
                            });
                        },
                        Err(e) => {
                            println!("Failed acquiring tcp lock with: {}", e);
                        }
                    }
                    //stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"OpEnd\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());
                },
                _ => {

                }
            }
                            

        }
        Err(err) => {
            
            //println!("Error parsing event schema: {:?}", err)
        },
    };
}

//type Cb = dyn FnMut(&EventRecord, &SchemaLocator) + Send + Sync + 'static;

//#[derive(Debug)]
struct EtwKernelFileTracker {
    trace: KernelTrace,
    fileobjects: Arc<Mutex<HashMap<u64, String>>>,
    stream_handle: Arc<Mutex<TcpStream>>
}

impl EtwKernelFileTracker {
    fn new<T>(mut callback: T, stream_handle: Arc<Mutex<TcpStream>>) -> Result<EtwKernelFileTracker, TraceError>
    where T: FnMut(&EventRecord, &SchemaLocator, &Mutex<HashMap<u64, String>>, &Mutex<TcpStream>)
        + Send + Sync + 'static 
    { 
        let map = Arc::new(Mutex::new(HashMap::new()));


        let file_provider = Provider::kernel(&KernelProvider::new(GUID::from("90cbdc39-4a3e-11d1-84f4-0000f80464e3"),EVENT_TRACE_FLAG_FILE_IO|EVENT_TRACE_FLAG_FILE_IO_INIT|EVENT_TRACE_FLAG_DISK_FILE_IO))
        .add_callback({
            let map = Arc::clone(&map);
            let stream = Arc::clone(&stream_handle);
            move |record, schema_locator| callback.borrow_mut()(record, schema_locator, &map, &stream)
        })
        .build();

        match KernelTrace::new()
        .named(String::from("etw_tracer"))
        .enable(file_provider)
        .start_and_process() {
            Ok(kernel_trace) => {
                return Ok(EtwKernelFileTracker{trace: kernel_trace, fileobjects: map, stream_handle})
            },
            Err(e) => {
                match e {
                    TraceError::EtwNativeError(ferrisetw::native::EvntraceNativeError::AlreadyExist) => {
                        stop_trace_by_name("etw_tracer");
                        return EtwKernelFileTracker::new(fileio_callback, stream_handle);
                    },
                    err => {
                        return Err(err);
                    }
                }
            },
        }         
    }
} 

fn windows_init(){
    println!("Initializing agent for Windows env...");
}

fn usage() {
    print!("Usage; {} ip:port 
         \nFallsback to default settings if nothing is provided.", std::env::current_exe().unwrap_or(Path::new("./app").to_path_buf()).to_str().unwrap_or("./app"));
}

fn parse_args() -> SocketAddrV4 {
    let mut args = std::env::args();
    match args.len() {
        1 => {
            println!("default settings");
            return SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 45678);
        },
        2 => {
            println!("got arg: {:?} parsing..", args);
            let _ = args.next();
            let arg = args.next().unwrap();
            println!("{}", arg);
            let txt = arg.split_once(':');
            match txt {
                Some((ip_str, port_str)) => {
                    let ip:Ipv4Addr = ip_str.parse().unwrap();
                    let port:u16 = port_str.parse().unwrap();

                    let target = SocketAddrV4::new(ip, port);
                    println!("Parsed target: {:?}", target);
                    return target;
                },
                None => {
                    println!("Error parsing {:?}", txt);
                    usage();
                    exit(-1);
                }
            }
        },
        _ => {
            println!("Got too many args: {:?}", args);
            usage();
            exit(-1);
        }
    }
}

use serde_json::json;

fn main() -> Result<(), io::Error> {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

    let es_target = parse_args();
    let url = format!("{}",es_target.to_string());
    println!("Connecting elasticsearch agent on {}", url);
    
    match TcpStream::connect(url){
        Ok(mut stream) => {
            stream.write_all(b"Connected to agent");
            println!("Connected to agent");
        
            let stream_handle = Arc::new(Mutex::new(stream));
        
            if cfg!(windows){
                windows_init();
                let file_etw = EtwKernelFileTracker::new(fileio_callback, stream_handle);
                std::thread::sleep(Duration::new(60, 0));//TODO
                Ok(())
            }else{
                todo!();
            }
        },
        Err(e) => {
            println!("Error connecting to TCP Stream: {}", e);
            return Err(e)
        }
    }
    
    
    //when the trace drops it automatically stops
}

fn init_winapihook(){

}


