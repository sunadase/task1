use ferrisetw::parser::{Parser, Pointer};
use ferrisetw::provider::kernel_providers::KernelProvider;
use ferrisetw::{provider::*, schema_locator, GUID};
use ferrisetw::schema_locator::SchemaLocator;
use ferrisetw::trace::*;
use ferrisetw::EventRecord;
use serde::Serialize;
use windows::Win32::System::Diagnostics::Etw;
use std::borrow::{Borrow, BorrowMut};
use std::cell::RefCell;
use std::collections::HashMap;
use std::env::Args;
use std::error::Error;
use std::fs::File;
use std::future::{Future, IntoFuture};
use std::hash::Hash;
use std::io::Write;
use std::net::{AddrParseError, IpAddr, Ipv4Addr, SocketAddrV4, TcpStream};
use std::process::exit;
use std::rc::Rc;
use std::sync::{Arc, Mutex};
use std::time::Duration;



pub const EVENT_TRACE_FLAG_FILE_IO: u32 = 0x02000000;
pub const EVENT_TRACE_FLAG_FILE_IO_INIT: u32 = 0x04000000;
pub const EVENT_TRACE_FLAG_DISK_FILE_IO: u32 = 0x00000200;

trait Repr {
    fn to_string(&self) -> String;
}

#[derive(Debug)]
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


#[derive(Debug)]
struct FileCreate{
    irpptr:Pointer,
    ttid:Pointer,
    file_object:Pointer,
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
        FileCreate{irpptr,ttid,file_object,create_options,file_attributes,share_access,open_path}
    }
}
impl Repr for FileCreate {
    fn to_string(&self) -> String {
        return format!("\"irpptr\":{},\"ttid\":{},\"file_object\":{},\"create_options\":{},\"file_attributes\":{},\"share_access\":{},\"open_path\":\"{}\"", self.irpptr, self.ttid, self.file_object, self.create_options, self.file_attributes, self.share_access, self.open_path);
    }
}

#[derive(Debug)]
struct FileReadWrite{
    file_key:u64,
    file_object:u64,
    iosize:u32,
    offset:u64 
}

impl FileReadWrite {
    fn new(parser: &Parser) -> Self{
        let file_key:u64 = parser.try_parse("FileKey").unwrap_or(0);
        let file_object:u64 = parser.try_parse("FileObject").unwrap_or(0);
        let iosize:u32 = parser.try_parse("IoSize").unwrap_or(0);
        let offset:u64 = parser.try_parse("Offset").unwrap_or(0);
        FileReadWrite{file_key, file_object, iosize, offset}
    }
}
impl Repr for FileReadWrite {
    fn to_string(&self) -> String {
        return format!("\"file_key\":{},\"file_object\":{},\"iosize\":{},\"offset\":{}", self.file_key, self.file_object, self.iosize, self.offset);
    }
}


#[derive(Debug)]
struct FileSimpleOp {
    irpptr:Pointer,
    ttid:Pointer, 
    file_object:Pointer,
    file_key:u64 
}
impl FileSimpleOp {
    fn new(parser: &Parser) -> Self {
        let irpptr:Pointer = parser.try_parse("IrpPtr").unwrap_or_default();
        let ttid:Pointer = parser.try_parse("TTID").unwrap_or_default();
        let file_object:Pointer = parser.try_parse("FileObject").unwrap_or_default();
        let file_key:u64 = parser.try_parse("FileKey").unwrap_or(0);
        FileSimpleOp{irpptr, ttid, file_object, file_key}
    }
}
impl Repr for FileSimpleOp {
    fn to_string(&self) -> String {
        return format!("\"irpptr\":{},\"ttid\":{},\"file_object\":{},\"file_key\":{}", self.irpptr, self.ttid, self.file_object, self.file_key);
    }
}

#[derive(Debug)]            
struct FileInfo{
    irpptr:Pointer,
    ttid:Pointer,
    file_object:Pointer,
    file_key:u64,
    extra_info:Pointer,
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
        FileInfo{irpptr, ttid, file_object,file_key,extra_info,info_class}
    }
}
impl Repr for FileInfo {
    fn to_string(&self) -> String {
        return format!("\"irpptr\":{},\"ttid\":{},\"file_object\":{},\"file_key\":{},\"extra_info\":{},\"info_class\":{}", self.irpptr, self.ttid, self.file_object, self.file_key, self.extra_info, self.info_class);
    }
}

#[derive(Debug)]
struct FileEndOp{
    irpptr:Pointer,
    extra_info:Pointer,
    nt_status:u32
}
impl FileEndOp {
    fn new(parser:&Parser) -> Self{
        let irpptr:Pointer = parser.try_parse("IrpPtr").unwrap_or_default();
        let extra_info:Pointer = parser.try_parse("ExtraInfo").unwrap_or_default();
        let nt_status:u32 = parser.try_parse("NtStatus").unwrap_or(0);
        FileEndOp{irpptr, extra_info, nt_status}
    }
}
impl Repr for FileEndOp {
    fn to_string(&self) -> String {
        return format!("\"irpptr\":{},\"extra_info\":{},\"nt_status\":{}", self.irpptr, self.extra_info, self.nt_status);
    }
}

fn fileio_callback(record: &EventRecord, schema_locator: &SchemaLocator, file_objects_record: &Mutex<HashMap<u64,String>>, stream: &Mutex<TcpStream>) {
    match schema_locator.event_schema(record) {
        Ok(schema) => {
            let parser = Parser::create(record, &schema);
            println!("[-] {} - {} - {} - {} - {} - {} - {} - {}",schema.provider_name(), schema.task_name(), schema.opcode_name(), record.event_flags(), record.opcode(), record.process_id(), record.thread_id() , record.raw_timestamp());
            match record.opcode() {
                0|32|35|36 => {//name
                    let event = FileName::new(&parser);
                    file_objects_record.lock().unwrap().insert(event.file_object.clone(), event.file_name.clone());
                    stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"Name\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());
                },
                64 => {//create
                    let event = FileCreate::new(&parser);
                    stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"Create\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());
                },
                67|68 => {//readwrite
                    let nf = String::from("Not found");
                    let event = FileReadWrite::new(&parser);
                    let file_name;
                    {
                        let map_guard = file_objects_record.lock().unwrap();
                        file_name = map_guard.get(&event.file_key).unwrap_or(&nf).clone();
                    }
                    stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"ReadWrite\", {}, \"file_name\":\"{}\"}}\n",record.process_id(), schema.opcode_name(), &event.to_string(), &file_name)).as_bytes());
                },
                65|66|73 => {//simpleop
                    let event = FileSimpleOp::new(&parser);
                    stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"SimpleOp\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());
                },
                69|70|71|74|75 => {//info
                    let event = FileInfo::new(&parser);
                    stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"Info\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());
                },
                76 => {//opEnd
                    let event = FileEndOp::new(&parser);
                    stream.lock().unwrap().write_all((format!("{{\"pid\":{}, \"event\":\"{}\", \"struct\":\"OpEnd\", {}}}\n",record.process_id(), schema.opcode_name(), &event.to_string())).as_bytes());

                },
                _ => {

                }
            }
                            

        }
        Err(err) => println!("Error {:?}", err),
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
    fn new<T>(mut callback: T, stream_handle: Arc<Mutex<TcpStream>>) -> EtwKernelFileTracker
    where T: FnMut(&EventRecord, &SchemaLocator, &Mutex<HashMap<u64, String>>, &Mutex<TcpStream>)
        + Send + Sync + 'static 
    { 
        let map = Arc::new(Mutex::new(HashMap::new()));


        let file_provider = Provider::kernel(&KernelProvider::new(GUID::from("90cbdc39-4a3e-11d1-84f4-0000f80464e3"),EVENT_TRACE_FLAG_FILE_IO|EVENT_TRACE_FLAG_FILE_IO_INIT|EVENT_TRACE_FLAG_DISK_FILE_IO))
        .add_callback({
            let map = Arc::clone(&map);
            let stream = Arc::clone(&stream_handle);
            move |record, schema_locator| callback(record, schema_locator, &map, &stream)
        })
        .build();

        let kernel_trace = KernelTrace::new()
        .named(String::from("etw_tracer"))
        .enable(file_provider)
        .start_and_process()
        .unwrap();
        
        return EtwKernelFileTracker{trace: kernel_trace, fileobjects: map, stream_handle}
    }
} 

fn windows_init(){
    println!("Initializing agent for Windows env...");
}

fn usage() {
    print!("Usage; {} ip:port 
         \nFallsback to default settings if nothing is provided.", std::env::current_exe().unwrap().file_name().unwrap().to_str().unwrap());
}

fn parse_args() -> SocketAddrV4 {
    let mut args = std::env::args();
    match args.len() {
        1 => {
            println!("default settings");
            return SocketAddrV4::new(Ipv4Addr::new(127,0,0,1), 8080);
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

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::init(); // this is optional. This makes the (rare) error logs of ferrisetw to be printed to stderr

    let es_target = parse_args();
    let url = format!("{}",es_target.to_string());
    println!("Connecting elasticsearch agent on {}", url);
    
    let mut stream = TcpStream::connect(url).unwrap();
    stream.write_all(b"Connected to agent");

    let stream_handle = Arc::new(Mutex::new(stream));

    if cfg!(windows){
        windows_init();
        let file_etw = EtwKernelFileTracker::new(fileio_callback, stream_handle);
        std::thread::sleep(Duration::new(60, 0));//TODO
    }else{
        todo!();
    }
    
    
    
    
    Ok(())
    //when the trace drops it automatically stops
}

fn init_winapihook(){

}


