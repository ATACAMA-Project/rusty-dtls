#![macro_use]

macro_rules! print_bytes {
    ($label:expr, $bytes:expr) => {
        trace!("{}", $label);
        if $bytes.len() == 0 {
            trace!("    -");
        } else {
            $bytes.chunks(16).for_each(|chunk| {
                let mut chunk_str = [b' '; 4 + 16 * 3 + 1 + 16];
                let mut pos = 4;
                chunk_str[4 + 16 * 3] = b'|';
                chunk.iter().enumerate().for_each(|(ind, byte)| {
                    let byte_1 = byte & 0xF;
                    let byte_2 = byte >> 4;
                    let translate = |b| if b > 9 { b - 10 + 97 } else { b + 48 };
                    chunk_str[pos] = translate(byte_2);
                    pos += 1;
                    chunk_str[pos] = translate(byte_1);
                    pos += 1;
                    chunk_str[pos] = b' ';
                    pos += 1;
                    chunk_str[4 + 16 * 3 + 1 + ind] =
                        if *byte < 32 || *byte > 126 { 46 } else { *byte };
                });

                trace!("{}", unsafe { core::str::from_utf8_unchecked(&chunk_str) });
            });
        }
    };
}
