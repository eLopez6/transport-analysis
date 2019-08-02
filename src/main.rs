mod headers;

extern crate typenum;
extern crate bit_array;
extern crate clap;

use crate::headers::convert_4bits_to_num;
use crate::headers::{Etherhdr, Iphdr, Tcphdr, Udphdr};
use typenum::{U4};
use bit_array::BitArray;
use clap::{Arg, App};
use std::path::Path;

const MAX_ETH_PKT: usize = 1518;
const ENDPOINT_MEMBERS: usize = 2;

struct PktMetaInfo {
    seconds: u32,
    microseconds: u32,
    caplen: u16,
    ignored: u16
}

impl PktMetaInfo {
    fn new() -> PktMetaInfo {
        PktMetaInfo {
            seconds      : 0,
            microseconds : 0,
            caplen       : 0,
            ignored      : 0
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
    packet_bytes: [u8; MAX_ETH_PKT],
    packet_type: PacketType,
    timestamp   : f64
}

impl PktInfo {

    // create new PktInfo
    // fn new(meta: PktMetaInfo, )
    fn new(meta: PktMetaInfo) -> PktInfo {
        
    }



    // reset the PktInfo for new processing

    // fn reset(&self) {
    //     s;

    // }
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
    sample_program();
}

fn sample_program() {
    let mut arr = BitArray::<u32, U4>::from_elem(false);
    arr.set(3, true);
    let conversion = convert_4bits_to_num(arr);
    println!("{}", conversion);
}

fn connection_summaries(filename_str: &str) {

}


fn packet_dumping(filename_str: &str) {

}

fn roundtrip_times(filename_str: &str) {

}


fn next_packet(packetInfo: &PktInfo) -> bool {


    return true     // the next packet is successfully read
}

fn error_exit(err_message: String) {
    eprintln!("Error in Transport Analysis: {}!", err_message);
    std::process::exit(0);
}