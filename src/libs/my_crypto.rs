use crate::libs::result;
use base64;
use crypto::buffer::{BufferResult, ReadBuffer, WriteBuffer};
use crypto::{aes, blockmodes, buffer, symmetriccipher};

// 加密解密
pub fn my_crypto(content: &str, crypt: bool) -> Result<String, result::MyErr> {
    let key = "3ZmTfHY5pzgNN9m3+Y04/w==Yike5212";
    let iv: [u8; 16] = [3; 16];

    let data = match crypt {
        true => match aes256_cbc_encrypt(content.as_bytes(), &key.as_bytes(), &iv) {
            Ok(e) => base64::encode(e),
            Err(_) => {
                return Err(result::MyErr {
                    msg: String::from("AES加密错误"),
                })
            }
        },
        false => {
            let encrypt_data = match base64::decode(content) {
                Ok(e) => e,
                Err(_) => {
                    return Err(result::MyErr {
                        msg: String::from("Base64解码出错"),
                    })
                }
            };
            match aes256_cbc_decrypt(&encrypt_data, &key.as_bytes(), &iv) {
                Ok(e) => String::from_utf8(e).unwrap(),
                Err(_) => {
                    return Err(result::MyErr {
                        msg: String::from("AES解密出错"),
                    })
                }
            }
        }
    };

    Ok(data)
}
// aes 加密
fn aes256_cbc_encrypt(
    data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut encryptor =
        aes::cbc_encryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);
    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = encryptor.encrypt(&mut read_buffer, &mut write_buffer, true)?;

        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );

        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }
    Ok(final_result)
}

// aes 解密
fn aes256_cbc_decrypt(
    encrypted_data: &[u8],
    key: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, symmetriccipher::SymmetricCipherError> {
    let mut decryptor =
        aes::cbc_decryptor(aes::KeySize::KeySize256, key, iv, blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(encrypted_data);
    let mut buffer = [0; 4096];
    let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);

    loop {
        let result = decryptor.decrypt(&mut read_buffer, &mut write_buffer, true)?;
        final_result.extend(
            write_buffer
                .take_read_buffer()
                .take_remaining()
                .iter()
                .map(|&i| i),
        );
        match result {
            BufferResult::BufferUnderflow => break,
            BufferResult::BufferOverflow => {}
        }
    }

    Ok(final_result)
}

