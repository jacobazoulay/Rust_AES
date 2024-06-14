const AES_SBOX: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

const COL_MIX_MAT: [u8; 16] = [
    0x02, 0x01, 0x01, 0x03,
    0x03, 0x02, 0x01, 0x01,
    0x01, 0x03, 0x02, 0x01,
    0x01, 0x01, 0x03, 0x02
];

const RCON: [u8; 11] = [
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x00
];


fn round(state_arr: &[u8; 16], key_arr: &[u8; 16]) -> [u8; 16] {
    
    let mut xor_arr: [u8; 16] = xor(state_arr, key_arr);
    print_byte_array(&xor_arr);
    let mut next_key: [u8; 16] = *key_arr;
    for i in 0..10 {
        println!("\n\n\nRound {}", i+1);
        println!("\nInput {}:", i+1);
        print_byte_array(&xor_arr);

        let s_box_sub_array: [u8; 16] = sub_bytes(&xor_arr);
        println!("\nAfter s-box {}:", i+1);
        print_byte_array(&s_box_sub_array);
        
        let shift_array: [u8; 16] = shift_arr(&s_box_sub_array);
        println!("\nAfter permutation {}:", i+1);
        print_byte_array(&shift_array);

        let mixcol_array: [u8; 16] = mix_col(&shift_array);
        println!("\nAfter mult {}:", i+1);
        print_byte_array(&mixcol_array);
        
        next_key= calc_next_key(&next_key, i as usize);
        println!("\nUsed subkey {}:", i+1);
        print_byte_array(&next_key);

        // let xor_arr: [u8; 16];
        if i != 9 {
            xor_arr = xor(&mixcol_array, &next_key);
        } else {
            
             xor_arr= xor(&shift_array, &next_key);
        }
        
        println!("\nFinal state {}:", i+1);
        print_byte_array(&xor_arr);

    }

    // print_byte_array(&xor_arr);
    return xor_arr;

}


fn main() {
    let my_key: &str = "Thats my Kung Fu";
    let plaintext: &str = "Two One Nine Two";

    // Convert key to bytes and ensure it's exactly 16 bytes
    let my_key_bytes: [u8; 16] = my_key.as_bytes().try_into().expect("Key must be 16 bytes long");
    // Convert plaintext to bytes and ensure it's exactly 16 bytes
    let plaintext_bytes: [u8; 16] = plaintext.as_bytes().try_into().expect("Plaintext must be 16 bytes long");

    print_byte_array(&my_key_bytes);
    print_byte_array(&plaintext_bytes);

    round(&plaintext_bytes, &my_key_bytes);

    }

fn calc_next_key(byte_arr1: &[u8], round:usize) -> [u8; 16] {
    let mut last: [u8; 4] = [0; 4];
    last[..].copy_from_slice(&byte_arr1[12..16]);

    last = sub_key(&rot_word_key(&last));

    last[0] ^= RCON[round];


    let mut next_key: [u8; 16] = [0; 16];
    let first = xor_key(&byte_arr1[0..4], &last);

    // next_key[0..4] = first[..];
    next_key[0..4].copy_from_slice(&first[..]);

    for i in 1..4 {
        let temp = xor_key(&byte_arr1[(i * 4)..(i * 4 + 4)], &next_key[((i - 1) * 4)..((i - 1) * 4 + 4)]);
        next_key[(i * 4)..(i * 4 + 4)].copy_from_slice(&temp);
        // next_key[(i*4)..4+(i*4)].copy_from_slice(&xor_key(&byte_arr1[(i*4)..4+(i*4)], &next_key[((i-1)*4)..4+((i-1)*4)]));
    }

    return next_key;

}

fn rot_word_key(byte_word: &[u8]) -> [u8; 4] {
    let rotated: [u8; 4] = [byte_word[1], byte_word[2], byte_word[3], byte_word[0]];
    return rotated;
}

fn sub_key(byte_word: &[u8]) -> [u8; 4] {
    let mut subbed: [u8; 4] = [0; 4];
    for i in 0..4{
        subbed[i] = AES_SBOX[byte_word[i] as usize];
    }

    return subbed;
}

fn xor_key(byte_arr1: &[u8], byte_arr2: &[u8]) -> [u8; 4] {

    assert_eq!(byte_arr1.len(), byte_arr2.len());

    let mut new_state_array: [u8; 4] = [0; 4];
    for i in 0..byte_arr1.len() {
        let result: u8 = byte_arr1[i] ^ byte_arr2[i];
        new_state_array[i] = result;
    }

    return new_state_array;
}

fn mix_col(byte_arr1: &[u8]) -> [u8; 16] {
    let mut mixed_arr:[u8; 16] = [0; 16];
    for col in 0..4 {
        for row in 0..4 {
            let mut val: u8 = 0;
                for j in 0..4 {
                    let val_inter: u8 = mul(byte_arr1[col * 4 + j], COL_MIX_MAT[j*4 + row]);
                    val = val ^ val_inter;
                }
            mixed_arr[col * 4 + row] = val;
        }
    }

    return mixed_arr;
}

fn shift_arr(byte_arr: &[u8]) -> [u8;16] {
    let mut shifted_array: [u8; 16] = [0; 16];

    for i in 0..4 {
        for j in 0..4 {
            shifted_array[i*4 + j as usize] = byte_arr[(i*4 + j + j*4) % 16 as usize];
        }
    }
    return shifted_array;
}

fn xor(byte_arr1: &[u8], byte_arr2: &[u8]) -> [u8; 16] {

    assert_eq!(byte_arr1.len(), byte_arr2.len());

    let mut new_state_array: [u8; 16] = [0; 16];
    for i in 0..byte_arr1.len() {
        let result: u8 = byte_arr1[i] ^ byte_arr2[i];
        new_state_array[i] = result;
    }

    return new_state_array;
}

fn sub_bytes(byte_arr1: &[u8]) -> [u8; 16] {
    assert!(byte_arr1.len() == 16);

    let mut subbed_array: [u8; 16] = [0; 16];
    for (i, &item) in byte_arr1.iter().enumerate() {
        subbed_array[i] = AES_SBOX[item as usize];
    }

    return subbed_array;
}

// fn print_type_of<T>(_: &T) {
//     println!("{}", std::any::type_name::<T>())
// }

fn print_byte_array(byte_arr1: &[u8]) {
    for val in byte_arr1 {
        print!("{:02x}, ", val);
    }
    println!();
}

fn xtime(x: u8) -> u8 {
    let mut xtime_result = x << 1;
    if x & 0x80 != 0 {
        xtime_result ^= 0x1B; // Polynomial reduction
    }
    xtime_result
}

fn mul_by_02(x: u8) -> u8 {
    xtime(x)
}

fn mul_by_03(x: u8) -> u8 {
    xtime(x) ^ x
}

fn mul(a: u8, b: u8) -> u8 {
    match b {
        0x01 => a,
        0x02 => mul_by_02(a),
        0x03 => mul_by_03(a),
        _ => 0,
    }
}