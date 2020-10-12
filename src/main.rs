mod headers;

extern crate clap;

use crate::headers::{Etherhdr, Iphdr, Tcphdr, Udphdr};
use clap::{Arg, App};
use std::path::Path;
use std::fs::File;
use std::io::{Read, BufReader};

const MAX_ETH_PKT: usize = 1518;
const ENDPOINT_MEMBERS: usize = 2;

struct PktMetaInfo {
    seconds: u32,
    microseconds: u32,
    caplen: u16,
    ignored: u16
}

impl PktMetaInfo {
    fn new_empty() -> PktMetaInfo {
        PktMetaInfo {
            seconds      : 0,
            microseconds : 0,
            caplen       : 0,
            ignored      : 0
        }
    }

    fn new(seconds: u32, microseconds: u32, caplen: u16, ignored: u16) -> PktMetaInfo {
        PktMetaInfo {
            seconds: seconds,
            microseconds: microseconds,
            caplen: caplen,
            ignored: ignored
        }
    }
}

// convert to structs
enum PacketType {
    Unknown,
    EthPacket(Etherhdr),
    IpPacket (Etherhdr, Iphdr, u8),
    UdpPacket(Etherhdr, Iphdr, u8, Udphdr),
    TcpPacket(Etherhdr, Iphdr, u8, Tcphdr, u8),
}

// use more type fuckery to handle more illegal state
// i.e., if it aint Ethernet packet, we ain't concerned about its IP and TCP
// or like, if the IP header is incomplete, we aren't concerned about the TCP

// enum valid types, i.e., incomplete IP packet, valid TCP packet

struct PktInfo {
    meta: PktMetaInfo,
    packet_bytes: Vec<u8>,
    packet_type: PacketType,
    timestamp   : f64
}

impl PktInfo {

    // create new PktInfo
    // fn new(meta: PktMetaInfo, )
    fn new(meta: PktMetaInfo) -> PktInfo {
        PktInfo {
            meta : meta,
            packet_bytes : Vec::with_capacity(MAX_ETH_PKT),
            packet_type : PacketType::Unknown,
            timestamp : 0.0
        }
    }

}

// #[derive(Hash)]
struct TcpConnInfo {
    sequence: [u32; ENDPOINT_MEMBERS],
    seq_set : [bool; ENDPOINT_MEMBERS],
    rtt_calc: [bool; ENDPOINT_MEMBERS],
    first_ts: [f64; ENDPOINT_MEMBERS],
    last_ts : [f64; ENDPOINT_MEMBERS]
}

// #[derive(Hash)]
struct ConnectionInfo {
    start_ts  : f64,
    current_ts: f64,
    protocol  : u8,
    ips       : [u32; ENDPOINT_MEMBERS],
    ports     : [u16; ENDPOINT_MEMBERS],
    pkts      : [u32; ENDPOINT_MEMBERS],
    bytes     : [u32; ENDPOINT_MEMBERS],
    tcp_info  : Option<TcpConnInfo>
}

enum Opts {
    PacketDump,
    Summary,
    RTT,
    Missing
}

fn main() {
    let matches = App::new("Transport Analysis")
                        .version("1.0")
                        .author("Emilio")
                        .arg(Arg::with_name("r")
                            .short("r")
                            .value_name("FILE")
                            .help("Path of packet trace")
                            .takes_value(true)
                            .required(true))
                        .arg(Arg::with_name("p")
                            .short("p")
                            .help("Packet dumping"))
                        .arg(Arg::with_name("s")
                            .short("s")
                            .help("Connection summaries"))
                        .arg(Arg::with_name("t")
                            .short("t")
                            .help("Round trip times"))
                        .get_matches();

    let s_opt = matches.is_present("s");
    let p_opt = matches.is_present("p");
    let t_opt = matches.is_present("t");

    // Counting the options supplied in the argument
    let mut filename_arg = Opts::Missing;
    let mut opts_count = 0;
    if s_opt {
        opts_count = opts_count + 1;
        filename_arg = Opts::Summary;
    }
    if p_opt {
        opts_count = opts_count + 1;
        filename_arg = Opts::PacketDump;
    }
    if t_opt {
        opts_count = opts_count + 1;
        filename_arg = Opts::RTT;
    }

    if opts_count > 1 {
        error_exit("Too many printing options detected".to_string());
    } else if opts_count == 0 {
        error_exit("No option supplied".to_string());
    }

    let filename_str = matches.value_of("r").unwrap();

    match filename_arg {
        Opts::Summary    => connection_summaries(filename_str),
        Opts::PacketDump => packet_dumping(filename_str),
        Opts::RTT        => roundtrip_times(filename_str),
        Opts::Missing    => error_exit(String::from("Missing option"))
    }
}

fn connection_summaries(filename_str: &str) {

}


fn packet_dumping(filename_str: &str) {
    let display = Path::new(filename_str).display();

    let trace = match File::open(filename_str) {
        Err(why) => panic!("Failed to open {}: {}", display, why.to_string()),
        Ok(trace) => trace, 
    };
    let mut reader = BufReader::new(trace);
    
    let mut packet = PktInfo::new(PktMetaInfo::new_empty());

}

fn roundtrip_times(filename_str: &str) {

}

fn next_packet_meta(file_reader: &mut BufReader<File>) -> PktMetaInfo {
    let seconds = read_u32_from_file(file_reader);
    let microseconds = read_u32_from_file(file_reader);
    let caplen = read_u16_from_file(file_reader);
    let ignored = read_u16_from_file(file_reader);

    PktMetaInfo::new(seconds, microseconds, caplen, ignored)
}

// Move to library
fn read_u32_from_file(file_reader: &mut BufReader<File>) -> u32 {
    let mut buf32 = [0; 4];
    match file_reader.read_exact(&mut buf32) {
        Ok(()) => u32::from_ne_bytes(buf32),
        Err(why) => panic!("Error in Transport Analysis:\nFailed to read u32: {}", why.to_string())
    }
}


// Move to library
fn read_u16_from_file(mut file_reader: &mut BufReader<File>) -> u16 {
    let mut buf16 = [0; 2];
    match file_reader.read_exact(&mut buf16) {
        Ok(()) => u16::from_ne_bytes(buf16),
        Err(why) => panic!("Failed to read u16: {}", why.to_string())
    }
}

fn error_exit(err_message: String) {
    panic!("Error in Transport Analysis: {}!", err_message)
}