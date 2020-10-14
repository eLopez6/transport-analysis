use bitvec::array::BitArray;
use bitvec::order::Lsb0;

const MAC_LENGTH:  usize = 6;
const CRC_LENGTH:  usize = 4;

const OPTIONS_28: usize = 2;
const OPTIONS_32: usize = 3;
const OPTIONS_36: usize = 4;

pub const eth_hdr_len: usize = 14;
pub const ip_hdr_len: usize = 20;
pub const udp_hdr_len: usize = 8;

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
enum Options {
    Opts20,
    Opts24(u32),
    Opts28([u32; OPTIONS_28]),
    Opts32([u32; OPTIONS_32]),
    Opts36([u32; OPTIONS_36])
}

pub struct Iphdr {
    pub version       : BitArray<Lsb0, [usize; bitvec::mem::elts::<usize>(4)]>,     // 4 bits
    pub ihl           : BitArray<Lsb0, [usize; bitvec::mem::elts::<usize>(4)]>,     // 4 bits
    pub dscp          : BitArray<Lsb0, [usize; bitvec::mem::elts::<usize>(6)]>,     // 6 bits
    pub ecn           : BitArray<Lsb0, [usize; bitvec::mem::elts::<usize>(2)]>,     // 2 bits
    pub tot_len       : u16,
    pub identification: u16,
    pub flags         : BitArray<Lsb0, [usize; bitvec::mem::elts::<usize>(3)]>,      // 3 bits
    pub frag_offset   : BitArray<Lsb0, [usize; bitvec::mem::elts::<usize>(13)]>,     // 13 bits
    pub ttl           : u8,
    pub protocol      : u8,
    pub hdr_checksum  : u16,
    pub src_ip_adr    : u32,
    pub dst_ip_adr    : u32,
    pub options       : Option<Options>,
    pub head_length   : u8,
    pub malformed     : bool    // this is true when ihl*4 != the length of the packet
}
// impl Iphdr {
//     pub fn new() 
// }

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
    data_off   : BitArray<Lsb0, [usize; bitvec::mem::elts::<usize>(4)]>,    // 4 bits
    reserved   : BitArray<Lsb0, [usize; bitvec::mem::elts::<usize>(3)]>,    // 3 bits
    flags      : BitArray<Lsb0, [usize; bitvec::mem::elts::<usize>(9)]>,    // 9 bits
    window_size: u16,
    checksum   : u16, 
    urg_pointer: u16,
    options    : Option<Options>,
    head_length: u8,
    malformed  : bool   // this is true when the data_off*4 != the length of the packet
}

// Where the ith bit of the array 0b1000 => 3,2,1,0
fn convert_4bits_to_num(field: BitArray) -> u16 {
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
