#![no_std]
#![no_main]
use core::panic::PanicInfo;

use aes::Aes128;
use ecb::{Decryptor};
use ecb::cipher::{KeyInit};
use aes::cipher::{BlockDecryptMut, generic_array::GenericArray};

type Aes128EcbDec = Decryptor<Aes128>;

#[no_mangle]
pub extern "C" fn main() -> u32 {
    let key: &[u8; 16] = b"1234567890123456";
    let mut input: [u8; 16] = [0; 16];
    let output: [u8; 16] = [0; 16];

    stubs::_read(&mut input);
    let mut cipher = Aes128EcbDec::new(key.into());
    let in_block = GenericArray::from(input);
    let mut out_block = GenericArray::from(output);
    cipher.decrypt_block_b2b_mut(&in_block, &mut out_block);
    0
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    stubs::_exit(0xFF);
}
