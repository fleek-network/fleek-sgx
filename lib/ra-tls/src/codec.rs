use std::io::{Read, Write};
use std::ops::{Deref, DerefMut};

use anyhow::{anyhow, Result};
use rustls::{SideData, StreamOwned};

pub const SECRET_KEY_SIZE: usize = 32;
pub const PUBLIC_KEY_SIZE: usize = 33;

pub struct FramedStream<C: Sized, T: Read + Write + Sized> {
    inner: StreamOwned<C, T>,
}

impl<C, T, S> FramedStream<C, T>
where
    C: DerefMut + Deref<Target = rustls::ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    pub fn send(&mut self, message: Codec) -> Result<()> {
        message.send(&mut self.inner)
    }

    pub fn recv(&mut self) -> Result<Codec> {
        Codec::recv(&mut self.inner)
    }

    pub fn close(self) -> Result<()> {
        let (mut conn, mut stream) = self.inner.into_parts();

        conn.send_close_notify();
        conn.complete_io(&mut stream)?;
        Ok(())
    }
}

impl<C, T, S> From<StreamOwned<C, T>> for FramedStream<C, T>
where
    C: DerefMut + Deref<Target = rustls::ConnectionCommon<S>>,
    T: Read + Write,
    S: SideData,
{
    fn from(value: StreamOwned<C, T>) -> Self {
        Self { inner: value }
    }
}

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
    SecretKey([u8; SECRET_KEY_SIZE]),
    PublicKey([u8; PUBLIC_KEY_SIZE]),
    KeyNotFound,
}

impl Codec {
    pub fn send<W: Write>(&self, writer: &mut W) -> Result<()> {
        match self {
            Codec::Request(req) => match req {
                Request::GetKey => writer.write_all(&[0x01])?,
            },
            Codec::Response(res) => match res {
                Response::SecretKey(key) => {
                    writer.write_all(&[0xFF])?;
                    writer.write_all(key)?;
                },
                Response::PublicKey(key) => {
                    writer.write_all(&[0xFE])?;
                    writer.write_all(key)?;
                },
                Response::KeyNotFound => writer.write_all(&[0xFD])?,
            },
        }
        writer.flush()?;
        Ok(())
    }

    pub fn recv<R: Read>(reader: &mut R) -> Result<Self> {
        // TODO(matthias): wrap into BufReader?
        let mut magic = [0; 1];
        reader.read_exact(&mut magic)?;
        match magic[0] {
            0x01 => Ok(Codec::Request(Request::GetKey)),
            0xFF => {
                let mut key = [0; SECRET_KEY_SIZE];
                reader.read_exact(&mut key)?;
                Ok(Codec::Response(Response::SecretKey(key)))
            },
            0xFE => {
                let mut key = [0; PUBLIC_KEY_SIZE];
                reader.read_exact(&mut key)?;
                Ok(Codec::Response(Response::PublicKey(key)))
            },
            0xFD => Ok(Codec::Response(Response::KeyNotFound)),
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
        msg.send(&mut cursor).unwrap();

        cursor.seek(SeekFrom::Start(0)).unwrap();

        let msg_recv = Codec::recv(&mut cursor).unwrap();
        assert_eq!(msg, msg_recv);
    }

    #[test]
    fn test_response_key() {
        let mut cursor = Cursor::new(vec![0; 8]);

        let key = [9; 32];
        let msg = Codec::Response(Response::SecretKey(key));
        msg.send(&mut cursor).unwrap();

        cursor.seek(SeekFrom::Start(0)).unwrap();

        let msg_recv = Codec::recv(&mut cursor).unwrap();
        assert_eq!(msg, msg_recv);
    }

    #[test]
    fn test_two_messages() {
        let mut cursor = Cursor::new(vec![0; 8]);

        let msg1 = Codec::Request(Request::GetKey);
        msg1.send(&mut cursor).unwrap();

        let msg2 = Codec::Response(Response::KeyNotFound);
        msg2.send(&mut cursor).unwrap();

        cursor.seek(SeekFrom::Start(0)).unwrap();

        let msg1_recv = Codec::recv(&mut cursor).unwrap();
        let msg2_recv = Codec::recv(&mut cursor).unwrap();
        assert_eq!(msg1, msg1_recv);
        assert_eq!(msg2, msg2_recv);
    }
}
