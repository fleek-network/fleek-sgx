use std::io::Read;
use std::net::TcpStream;

use arrayref::array_ref;

use crate::b3_verify::hasher::byte_hasher::BlockHasher;
use crate::b3_verify::hasher::collector::BufCollector;
use crate::b3_verify::verifier::{IncrementalVerifier, WithHashTreeCollector};

const LEADING_BIT: u32 = 1 << 31;

/// Get some verified content from the userland.
pub fn get_verified_content(hash: &[u8; 32]) -> anyhow::Result<([u8; 32], Vec<u8>)> {
    let hash_hex = hex::encode(hash);
    let raw = *array_ref![hash, 0, 32];

    let mut stream = TcpStream::connect(&format!("{hash_hex}.blockstore.fleek.network"))
        .expect("failed to connect to blockstore content stream");

    let mut verifier = IncrementalVerifier::<WithHashTreeCollector<BufCollector>>::default();
    verifier.set_root_hash(*hash);

    // TODO: use userspace memory allocations to avoid having public data
    //       held in the precious and limited protected memory space.
    let mut content = Vec::new();
    let mut block = 0;

    loop {
        // read leading chunk bit and length delimiter
        let mut buf = [0; 4];
        stream.read_exact(&mut buf)?;
        let mut len = u32::from_be_bytes(buf);
        let is_proof = LEADING_BIT & len == 0;

        if len == LEADING_BIT {
            // stream finished
            break;
        }

        // unset leading bit
        len &= !LEADING_BIT;

        // read payload
        let mut payload = vec![0; len as usize];
        stream.read_exact(&mut payload)?;

        if is_proof {
            verifier.feed_proof(&payload)?;
        } else {
            let mut hasher = BlockHasher::default();
            hasher.set_block(block as usize);

            hasher.update(&payload);
            let exp_hash = hasher.finalize(false);
            verifier.verify_hash(exp_hash)?;

            // TODO(matthias): do we need this?
            //if content.len() + payload.len() >= ARGS.wasm_config.max_blockstore_size {
            //    bail!("blockstore content too large")
            //}

            content.append(&mut payload);
            block += 1;
        }
    }

    println!("enclave received verified content");
    Ok((raw, content))
}
