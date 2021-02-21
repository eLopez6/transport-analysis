mod headers;

extern crate clap;

use crate::headers::{Etherhdr, Iphdr, Tcphdr, Udphdr, Options, eth_hdr_len, ip_hdr_len, udp_hdr_len, tcp_hdr_len};
use clap::{Arg, App};
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, BufReader};
use std::path::Path;

const META_INFO_SIZE: usize = 12;
const MAX_ETH_PKT: usize = 1518;
const ENDPOINT_MEMBERS: usize = 2;
const FIRST_NIBBLE:  u8 = 0b11110000;
const SECOND_NIBBLE: u8 = 0b00001111;
const MICROSECONDS_PER_SECOND: f64 = 1000000.0;
const IP_PROTOCOL: u16 = 2048;
const IPV4_PROTOCOL: u8 = 4;
const TCP_PROTOCOL: u8 = 6;
const UDP_PROTOCOL: u8 = 17;

#[derive(Clone,Copy)]
struct PktMetaInfo {
    seconds: u32,
    microseconds: u32,
    caplen: u16,
    ignored: u16
}

impl PktMetaInfo {

fn new(seconds: u32, microseconds: u32, caplen: u16, ignored: u16) -> PktMetaInfo {
        PktMetaInfo {
            seconds: seconds,
            microseconds: microseconds,
            caplen: caplen,
            ignored: ignored
        }
    }
}
#[derive(Clone)]
enum PacketType {
    Unknown,
    EthPacket(Etherhdr),
    IpPacket (Etherhdr, Iphdr),
    UdpPacket(Etherhdr, Iphdr, Udphdr),
    TcpPacket(Etherhdr, Iphdr, Tcphdr),
}

// use more type fuckery to handle more illegal state
// i.e., if it aint Ethernet packet, we ain't concerned about its IP and TCP
// or like, if the IP header is incomplete, we aren't concerned about the TCP

// enum valid types, i.e., incomplete IP packet, valid TCP packet

#[derive(Clone)]
struct PktInfo {
    meta: PktMetaInfo,
    packet_type: PacketType,
    timestamp   : f64
}

impl PktInfo {
    fn new_unknown(meta: PktMetaInfo) -> PktInfo {
        PktInfo {
            meta : meta,
            packet_type : PacketType::Unknown,
            timestamp : 0.0
        }
    }

    fn new(meta: PktMetaInfo, packet_type: PacketType) -> PktInfo {
        PktInfo {
            meta : meta,
            packet_type : packet_type,
            timestamp : f64::from(meta.seconds) + 
                (f64::from(meta.microseconds) / MICROSECONDS_PER_SECOND)
        }
    }
}

// #[derive(Hash)]
// try to find a crate for timestamps
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
        error_exit("Too many printing options detected");
    } else if opts_count == 0 {
        error_exit("No option supplied");
    }

    let filename_str = matches.value_of("r").unwrap();

    match filename_arg {
        Opts::Summary    => connection_summaries(filename_str),
        Opts::PacketDump => packet_dumping(filename_str),
        Opts::RTT        => roundtrip_times(filename_str),
        Opts::Missing    => error_exit("Missing option")
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

    let mut cur_packet = next_packet(&mut reader);
    while cur_packet.is_some() {

        // TODO implement printing of values from packet


        cur_packet = next_packet(&mut reader);
    }

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

fn next_packet(file_reader: &mut BufReader<File>) -> Option<PktInfo> {
    let packet_meta_info = next_packet_meta(file_reader);

    if packet_meta_info.caplen == 0 {
        None
    } else {
        if packet_meta_info.caplen > MAX_ETH_PKT as u16 {
            error_exit("Packet size is larger than MAX_ETH_PKT");
        }
    
        let packet_length: usize = (packet_meta_info.caplen - META_INFO_SIZE as u16).into();
        let mut packet_buffer = vec![0u8; packet_length];
        match file_reader.read_exact(&mut packet_buffer) {
            Err(why) => panic!("Error in  Transport Analysis:\nFailed to read the packet: {}", why.to_string()),
            Ok(()) => {
                let ether_header = next_eth_packet(file_reader);
                match ether_header.typ {
                    IP_PROTOCOL => {
                        let ip_header = next_ip_packet(file_reader, &packet_meta_info);
                        match ip_header.protocol {
                            IPV4_PROTOCOL => {
                                match ip_header.protocol {
                                    TCP_PROTOCOL => {
                                        let tcp_header = next_tcp_packet(file_reader, &packet_meta_info);
                                        Some(PktInfo::new(packet_meta_info, 
                                            PacketType::TcpPacket(ether_header, ip_header, tcp_header)))
                                    },
                                    UDP_PROTOCOL => {
                                        let udp_header = next_udp_packet(file_reader);
                                        Some(PktInfo::new(packet_meta_info, 
                                            PacketType::UdpPacket(ether_header, ip_header, udp_header)))
                                    }
                                    _ =>  Some(PktInfo::new(packet_meta_info, PacketType::IpPacket(ether_header, ip_header)))
                                }
                            },
                            _ => Some(PktInfo::new(packet_meta_info, PacketType::IpPacket(ether_header, ip_header)))                    
                        }
    
                    },   
                    _    => Some(PktInfo::new(packet_meta_info, PacketType::EthPacket(ether_header)))    // skip the packet completely
                     
                }
            }
        }
    }
}

fn next_eth_packet(file_reader: &mut BufReader<File>) -> Etherhdr {
    let mut packet_buffer = vec![0u8; eth_hdr_len];
    match file_reader.read_exact(&mut packet_buffer) {
        Err(why) => panic!("Error in Transport Analysis:\n Failed to read the packet: {}", why.to_string()),
        Ok(()) => {
            let src_addr  = mac_slice_to_array(&packet_buffer[0..5]);
            let dest_addr = mac_slice_to_array(&packet_buffer[6..11]);
            let typ = bytes_to_u16(&packet_buffer[12..]);
            Etherhdr::new(src_addr, dest_addr, typ)
        }
    }
}

fn next_ip_packet(file_reader: &mut BufReader<File>, packet_meta_info: &PktMetaInfo) -> Iphdr {
    let mut packet_buffer = vec![0u8; ip_hdr_len];
    match file_reader.read_exact(&mut packet_buffer) {
        Err(_) => Iphdr::malformed_header(),
        Ok(()) => {
            let cur_slice = u8::from_be(packet_buffer[0]);
            let ip_ver = cur_slice & FIRST_NIBBLE >> 4;
            let ihl = cur_slice & SECOND_NIBBLE;

            match ip_ver {
                4 => {
                    // abstract into its own method
                    let options = match ihl {
                        5 => Options::Opts20,
                        6 => Options::Opts24,
                        7 => Options::Opts28,
                        8 => Options::Opts32,
                        _ => Options::Malformed
                    };

                    // move this around maybe
                    let header_len = ihl * 5;
                    let min_length = u16::from(header_len) + eth_hdr_len as u16;
                    if packet_meta_info.caplen < min_length {
                        return Iphdr::malformed_header()
                    }

                    match options {
                        Options::Malformed => Iphdr::malformed_header(),
                        _ => {
                            let dscp = u8::from_be(packet_buffer[1] & 0b11111100 >> 2);
                            let ecn  = u8::from_be(packet_buffer[1] & 0b00000011);
                            let total_len = bytes_to_u16(&packet_buffer[2..3]);
                            let id = bytes_to_u16(&packet_buffer[4..5]);
        
                            let frags_and_flags_slice = bytes_to_u16(&packet_buffer[6..7]);
                            let flags = u8::from_be((frags_and_flags_slice & 0xE000 >> 13) as u8);    // this will certainly cause issues
                            let frags = frags_and_flags_slice & 0x1FFF;
                            let ttl = u8::from_be(packet_buffer[8]);
                            let protocol = u8::from_be(packet_buffer[9]);
                            let hdr_checksum = bytes_to_u16(&packet_buffer[10..11]);
                            let src_ip = bytes_to_u32(&packet_buffer[12..15]);
                            let dst_ip = bytes_to_u32(&packet_buffer[16..]);
        
                            Iphdr::new(ip_ver, ihl, dscp, ecn, 
                                total_len, id, flags, frags, ttl, protocol,
                                 hdr_checksum, options, 
                                 src_ip, dst_ip, header_len)
                        }
                    }
                }
                _ => {
                    Iphdr::ignored_ver_header(ip_ver)
                }
            }
        }
    }
    
}

fn next_udp_packet(file_reader: &mut BufReader<File>) -> Udphdr {
    let mut packet_buffer = vec![0u8; udp_hdr_len];
    match file_reader.read_exact(&mut packet_buffer) {
        Err(why) => panic!("Error in Transport Analysis:\nFailed to read the packet: {}", why.to_string()),
        Ok(()) => {
            let src_port = bytes_to_u16(&packet_buffer[0..1]);
            let dst_port = bytes_to_u16(&packet_buffer[2..3]);
            let length = bytes_to_u16(&packet_buffer[4..5]);
            let checksum = bytes_to_u16(&packet_buffer[6..]);
            Udphdr::new(src_port, dst_port, length, checksum)
        }
    }
}

fn next_tcp_packet(file_reader: &mut BufReader<File>, packet_meta_info: &PktMetaInfo) -> Tcphdr {
    let mut packet_buffer = vec![0u8; tcp_hdr_len];
    match file_reader.read_exact(&mut packet_buffer) {
        Err(why) => panic!("Error in Transport Analysis:\n Failed to read the packet: {}", why.to_string()),
        Ok(()) => {
            let src_port = bytes_to_u16(&packet_buffer[0..1]);
            let dst_port = bytes_to_u16(&packet_buffer[2..3]);
            let seq_num = bytes_to_u32(&packet_buffer[4..7]);
            let ack_num = bytes_to_u32(&packet_buffer[8..11]);
            let fields = bytes_to_u16(&packet_buffer[12..13]);

            let data_off = u8::from_be((fields & 0xF000 >> 12).try_into().unwrap());
            let reserved = u8::from_be((fields & 0x0300 >> 9).try_into().unwrap());
            let flags = u16::from_be(fields & 0x01FF);

            // abstract into its own method
            let options = match data_off {
                5 => Options::Opts20,
                6 => Options::Opts24,
                7 => Options::Opts28,
                8 => Options::Opts32,
                _ => Options::Malformed
            };

            let header_len = 5 * data_off;
            let min_length = u16::from(header_len) + (eth_hdr_len + ip_hdr_len + tcp_hdr_len) as u16;
            if packet_meta_info.caplen < min_length {
                return Tcphdr::malformed_header();
            }

            let window_size = bytes_to_u16(&packet_buffer[14..15]); 
            let checksum = bytes_to_u16(&packet_buffer[16..17]);
            let urg = bytes_to_u16(&packet_buffer[18..]);

            // Tcphdr::malformed_header()
            Tcphdr::new(src_port, dst_port, seq_num, ack_num, data_off, reserved,
                flags, window_size, checksum, 
                urg, options, header_len)
        }
    }
}

fn mac_slice_to_array(mac_slice: &[u8]) -> [u8; 6] {
    match mac_slice.try_into() {
        Ok(mac) => mac,
        Err(_) => panic!("Error in Transport Analysis:\nFailed to convert MAC slice.")
    }
}

// rename
fn bytes_to_u16(type_slice: &[u8]) -> u16 {
    match type_slice.try_into() {
        Ok(typ) => u16::from_ne_bytes(typ),
        Err(_) => panic!("Error in Transport Analysis:\nFailed to convert Type slice.")
    }
}

fn bytes_to_u32(bytes: &[u8]) -> u32 {
    match bytes.try_into() {
        Ok(num) => u32::from_ne_bytes(num),
        Err(why) => panic!("Obama style: {}", why)
    }
}

// Move to library
fn read_u32_from_file(file_reader: &mut BufReader<File>) -> u32 {
    let mut buf32 = [0; 4];
    match file_reader.read(&mut buf32) {
        Ok(0) => 0,
        Ok(_) => u32::from_ne_bytes(buf32),
        Err(why) => panic!("Error in Transport Analysis:\nFailed to read u32: {}", why.to_string())
    }
}

// Move to library
fn read_u16_from_file(file_reader: &mut BufReader<File>) -> u16 {
    let mut buf16 = [0; 2];
    match file_reader.read(&mut buf16) {
        Ok(0) => 0,
        Ok(_) => u16::from_ne_bytes(buf16),
        Err(why) => panic!("Failed to read u16: {}", why.to_string())
    }
}

fn error_exit(err_message: &str) {
    panic!("Error in Transport Analysis: {}!", err_message)
}