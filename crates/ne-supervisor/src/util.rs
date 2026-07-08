// SPDX-FileCopyrightText: 2026 Infrastacks LLC <eng@infrastacks.com>
// SPDX-License-Identifier: Apache-2.0

//! Small shared supervisor utilities.

use std::io::{self, ErrorKind};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncReadExt};

/// Read one newline-delimited frame, rejecting anything larger than `max`
/// bytes instead of growing the buffer without bound (memory-exhaustion `DoS`).
/// Reads at most `max + 1` bytes: if the newline has not arrived by then the
/// frame is over the cap and is rejected.
pub(crate) async fn read_capped_line<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    buf: &mut String,
    max: u64,
) -> io::Result<usize> {
    let mut limited = reader.take(max + 1);
    let n = limited.read_line(buf).await?;
    if n as u64 > max {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            "frame exceeds maximum size",
        ));
    }
    Ok(n)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::BufReader;

    #[tokio::test]
    async fn rejects_oversized_frame() {
        let data = [b'x'; 64];
        let mut reader = BufReader::new(&data[..]);
        let mut line = String::new();
        let err = read_capped_line(&mut reader, &mut line, 16)
            .await
            .expect_err("oversized frame must error");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
    }

    #[tokio::test]
    async fn accepts_frame_at_cap() {
        let data = b"hello\n";
        let mut reader = BufReader::new(&data[..]);
        let mut line = String::new();
        let n = read_capped_line(&mut reader, &mut line, 16).await.unwrap();
        assert_eq!(n, 6);
        assert_eq!(line, "hello\n");
    }
}
