extern crate typenum;
extern crate bit_array;

use bit_array::BitArray;
use typenum::{U2, U3, U4, U6, U13};


const MAC_LENGTH:  usize = 6;
const TYPE_LENGTH: usize = 2;
const CRC_LENGTH:  usize = 4;

const OPTIONS_28: usize = 2;
const OPTIONS_32: usize = 3;
const OPTIONS_36: usize = 4;

pub struct Etherhdr {
    preamble: u8,
    dest_adr: [u8; MAC_LENGTH],
    src_adr : [u8; MAC_LENGTH],
    typ     : [u8; TYPE_LENGTH],
    crc     : [u8; CRC_LENGTH]
}

// The same Options enum can be used for IP and TCP
enum Options {
    Opts20,
    Opts24(u32),
    Opts28([u32; OPTIONS_28]),
    Opts32([u32; OPTIONS_32]),
    Opts36([u32; OPTIONS_36])
}

pub struct Iphdr {
    version       : BitArray<u32, U4>,
    ihl           : BitArray<u32, U4>,
    dscp          : BitArray<u32, U6>,
    en            : BitArray<u32, U2>,
    tot_len       : u16,
    identification: u16,
    flags         : BitArray<u32, U3>,
    frag_offset   : BitArray<u32, U13>,
    ttl           : u8,
    protocol      : u8,
    hdr_checksum  : u16,
    src_ip_adr    : u32,
    dst_ip_adr    : u32,
    options       : Option<Options>,
    head_length   : u8,
    malformed     : bool    // this is true when ihl*4 != the length of the packet
}

pub struct Udphdr {
    src_port: u16,
    dst_port: u16,
    length  : u16,
    checksum: u16
}

pub struct Tcphdr {
    src_port   : u16,
    dst_port   : u16,
    seq_num    : u32,
    ack_num    : u32,
    data_off   : BitArray<u32, U4>,
    reserved   : BitArray<u32, U4>,
    flags      : u8,    // each flag is 1 bit
    window_size: u16,
    checksum   : u16, 
    urg_pointer: u16,
    options    : Option<Options>,
    head_length: u8,
    malformed  : bool
}

// Where the ith bit of the array 0b1000 => 3,2,1,0
pub fn convert_4bits_to_num(field: BitArray<u32, U4>) -> u16 {
    match field.get(3) {
        Some(true) => 32,    // 0b1000
        _          => match field.get(1) {
            Some(true) => 20,    // 0b0101
            _          => match field.get(0) {
                Some(true) => 28,    // 0b0111
                _          => 24     // 0b0110
            }
        }
    }
}
