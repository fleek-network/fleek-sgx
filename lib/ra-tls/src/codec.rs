use std::io::{Read, Write};

use anyhow::{anyhow, Result};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Codec {
    Request(Request),
    Response(Response),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    GetKey,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Response {
    Key(Vec<u8>),
    KeyNotFound,
}

impl Codec {
    pub fn write<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Codec::Request(req) => match req {
                Request::GetKey => writer.write_all(&[0x01])?,
            },
            Codec::Response(res) => match res {
                Response::Key(key) => {
                    writer.write_all(&[0xFF])?;
                    writer.write_all(&(key.len() as u32).to_le_bytes())?;
                    writer.write_all(key)?;
                },
                Response::KeyNotFound => writer.write_all(&[0xFE])?,
            },
        }
        writer.flush()?;
        Ok(())
    }

    pub fn read<R: Read>(reader: &mut R) -> Result<Self> {
        // TODO(matthias): wrap into BufReader?
        let mut magic = [0; 1];
        reader.read_exact(&mut magic)?;
        match magic[0] {
            0x01 => Ok(Codec::Request(Request::GetKey)),
            0xFF => {
                let mut length_bytes = [0; 4];
                reader.read_exact(&mut length_bytes)?;
                let length = u32::from_le_bytes(length_bytes);
                let mut key = vec![0; length as usize];
                reader.read_exact(&mut key)?;
                Ok(Codec::Response(Response::Key(key.to_vec())))
            },
            0xFE => Ok(Codec::Response(Response::KeyNotFound)),
            b => Err(anyhow!("Invalid magic byte: {b}")),
        }
    }
}

#[cfg(test)]
mod tests {

    use std::io::{Cursor, Seek, SeekFrom};

    use super::*;

    #[test]
    fn test_request_get_key() {
        let mut cursor = Cursor::new(vec![0; 8]);

        let msg = Codec::Request(Request::GetKey);
        msg.write(&mut cursor).unwrap();

        cursor.seek(SeekFrom::Start(0)).unwrap();

        let msg_recv = Codec::read(&mut cursor).unwrap();
        assert_eq!(msg, msg_recv);
    }

    #[test]
    fn test_response_key() {
        let mut cursor = Cursor::new(vec![0; 8]);

        let key = vec![1, 2, 3];
        let msg = Codec::Response(Response::Key(key));
        msg.write(&mut cursor).unwrap();

        cursor.seek(SeekFrom::Start(0)).unwrap();

        let msg_recv = Codec::read(&mut cursor).unwrap();
        assert_eq!(msg, msg_recv);
    }

    #[test]
    fn test_two_messages() {
        let mut cursor = Cursor::new(vec![0; 8]);

        let msg1 = Codec::Request(Request::GetKey);
        msg1.write(&mut cursor).unwrap();

        let msg2 = Codec::Response(Response::KeyNotFound);
        msg2.write(&mut cursor).unwrap();

        cursor.seek(SeekFrom::Start(0)).unwrap();

        let msg1_recv = Codec::read(&mut cursor).unwrap();
        let msg2_recv = Codec::read(&mut cursor).unwrap();
        assert_eq!(msg1, msg1_recv);
        assert_eq!(msg2, msg2_recv);
    }
}
