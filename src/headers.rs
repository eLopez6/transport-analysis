use bitvec::array::BitArray;
use bitvec::order::Lsb0;
use bitvec::prelude::*;

const MAC_LENGTH:  usize = 6;

pub const eth_hdr_len: usize = 14;
pub const ip_hdr_len:  usize = 20;
pub const udp_hdr_len: usize = 8;
pub const tcp_hdr_len: usize = 20;

#[derive(Clone)]
pub struct Etherhdr {
    pub src_adr : [u8; MAC_LENGTH],
    pub dest_adr: [u8; MAC_LENGTH],
    pub typ     : u16
}
impl Etherhdr {
    pub fn new(src_adr: [u8; MAC_LENGTH], dest_adr: [u8; MAC_LENGTH], typ: u16) -> Etherhdr {
        Etherhdr {
            src_adr: src_adr,
            dest_adr: dest_adr,
            typ: typ
        }
    }
}

// The same Options enum can be used for IP and TCP
#[derive(Clone)]
pub enum Options {
    Ignored,
    Malformed,
    Opts20,
    Opts24,
    Opts28,
    Opts32,
}

#[derive(Clone)]
pub struct Iphdr {
    pub version       : BitArray<Lsb0, [u8; bitvec::mem::elts::<u8>(4)]>,     // 4 bits
    pub ihl           : BitArray<Lsb0, [u8; bitvec::mem::elts::<u8>(4)]>,     // 4 bits
    pub dscp          : BitArray<Lsb0, [u8; bitvec::mem::elts::<u8>(6)]>,     // 6 bits
    pub ecn           : BitArray<Lsb0, [u8; bitvec::mem::elts::<u8>(2)]>,     // 2 bits
    pub tot_len       : u16,
    pub identification: u16,
    pub flags         : BitArray<Lsb0, [u8; bitvec::mem::elts::<u8>(3)]>,      // 3 bits
    pub frag_offset   : BitArray<Lsb0, [u16; bitvec::mem::elts::<u16>(13)]>,     // 13 bits
    pub ttl           : u8,
    pub protocol      : u8,
    pub hdr_checksum  : u16,
    pub src_ip_adr    : u32,
    pub dst_ip_adr    : u32,
    pub options       : Options,
    pub head_length   : u8,
    pub malformed     : bool    // this is true when ihl*4 != the length of the packet
}
impl Iphdr {
    pub fn malformed_header() -> Iphdr {
        Iphdr {
            malformed: true,
            tot_len: 0,
            identification: 0,
            ttl: 0,
            protocol: 0,
            hdr_checksum: 0,
            src_ip_adr: 0,
            dst_ip_adr: 0,
            options: Options::Malformed,
            head_length: 0,
            version: bitarr![Lsb0, u8; 0; 4],
            ihl: bitarr![Lsb0, u8; 0; 4],
            dscp: bitarr![Lsb0, u8; 0; 6],
            ecn: bitarr![Lsb0, u8; 0; 2],
            flags: bitarr![Lsb0, u8; 0; 3],
            frag_offset: bitarr![Lsb0, u16; 0; 13]
        }
    }

    pub fn ignored_ver_header(ip_ver: u8) -> Iphdr {
        Iphdr {
            malformed: false,
            tot_len: 0,
            identification: 0,
            ttl: 0,
            protocol: 0,
            hdr_checksum: 0,
            src_ip_adr: 0,
            dst_ip_adr: 0,
            options: Options::Ignored,
            head_length: 0,
            version: bitarr![Lsb0, u8; ip_ver; 4],
            ihl: bitarr![Lsb0, u8; 0; 4],
            dscp: bitarr![Lsb0, u8; 0; 6],
            ecn: bitarr![Lsb0, u8; 0; 2],
            flags: bitarr![Lsb0, u8; 0; 3],
            frag_offset: bitarr![Lsb0, u16; 0; 13]
        }
    }
    
    pub fn new(version: u8, ihl: u8, dscp: u8, ecn: u8, total_len: u16, id: u16,
        flags: u8, frags: u16, ttl: u8, protocol: u8, hdr_checksum: u16, 
        options: Options, src: u32, dst: u32, header_len: u8) -> Iphdr {

        let ver = bitarr![Lsb0, u8; version; 4];
        let ihl = bitarr![Lsb0, u8; ihl; 4];
        let dscp = bitarr![Lsb0, u8; dscp; 6];
        let ecn = bitarr![Lsb0, u8; ecn; 2];
        let flags = bitarr![Lsb0, u8; flags; 3];
        let frag_offset = bitarr![Lsb0, u16; frags; 13];

        Iphdr {
            version: ver,
            ihl: ihl,
            dscp: dscp,
            ecn: ecn,
            flags: flags,
            frag_offset: frag_offset,
            tot_len: total_len,
            identification: id,
            ttl: ttl,
            protocol: protocol,
            hdr_checksum: hdr_checksum,
            src_ip_adr: src,
            dst_ip_adr: dst,
            options: options,
            head_length: header_len,
            malformed: false
        }
    
    }
}

#[derive(Clone)]
pub struct Udphdr {
    pub src_port: u16,
    pub dst_port: u16,
    pub length  : u16,
    pub checksum: u16
}
impl Udphdr {

    pub fn malformed_header() -> Udphdr {
        Udphdr {
            src_port: 0,
            dst_port: 0,
            length: 0,
            checksum: 0
        }
    }

    pub fn new(src_port: u16, dst_port: u16, length: u16, checksum: u16) -> Udphdr {
        Udphdr {
            src_port: src_port,
            dst_port: dst_port,
            length: length,
            checksum: checksum
        }
    }
}

#[derive(Clone)]
pub struct Tcphdr {
    pub src_port   : u16,
    pub dst_port   : u16,
    pub seq_num    : u32,
    pub ack_num    : u32,
    pub data_off   : BitArray<Lsb0, [u8; bitvec::mem::elts::<u8>(4)]>,    // 4 bits
    pub reserved   : BitArray<Lsb0, [u8; bitvec::mem::elts::<u8>(3)]>,    // 3 bits
    pub flags      : BitArray<Lsb0, [u16; bitvec::mem::elts::<u16>(9)]>,    // 9 bits
    pub window_size: u16,
    pub checksum   : u16, 
    pub urg_pointer: u16,
    pub options    : Options,
    pub head_length: u8,
    pub malformed  : bool   // this is true when the data_off*4 != the length of the packet
}
impl Tcphdr {
    pub fn malformed_header() -> Tcphdr {
        Tcphdr {
            malformed: true,
            src_port    : 0,
            dst_port    : 0,
            seq_num     : 0,
            ack_num     : 0,
            data_off    : bitarr![Lsb0, u8; 0; 4],
            reserved    : bitarr![Lsb0, u8; 0; 3],
            flags       : bitarr![Lsb0, u16; 0; 9],
            window_size : 0,
            checksum    : 0,
            urg_pointer : 0,
            options     : Options::Malformed,
            head_length : 0
        }
    }

    pub fn new(src_port: u16, dst_port: u16, seq_num: u32, ack_num: u32, data_off: u8, reserved: u8,
        flags: u16, window_size: u16, checksum: u16, urg_pointer: u16, options: Options, header_length: u8) -> Tcphdr {
            Tcphdr {
                malformed: false,
                src_port    : src_port,
                dst_port    : dst_port,
                seq_num     : seq_num,
                ack_num     : ack_num,
                data_off    : bitarr![Lsb0, u8; data_off; 4],
                reserved    : bitarr![Lsb0, u8; reserved; 3],
                flags       : bitarr![Lsb0, u16; flags; 9],
                window_size : window_size,
                checksum    : checksum,
                urg_pointer : urg_pointer,
                options     : Options::Malformed,
                head_length : header_length
            }
        }
}

// Where the ith bit of the array 0b1000 => 3,2,1,0
fn convert_4bits_to_num(field: BitArray<Lsb0, [u8; bitvec::mem::elts::<u8>(4)]>) -> u16 {
    if field.len() != 4 {
        match field.get(3) {
            Some(true) => 32,                    // 0b1000
            _          => match field.get(1) {
                Some(true) => ip_hdr_len as u16,                // 0b0101
                _          => match field.get(0) {
                    Some(true) => 28,            // 0b0111
                    _          => 24             // 0b0110
                }
            }
        }
    }
    else {
        panic!("BitArray supplied has an invalid capacity: {}", field.len());
    }
}
