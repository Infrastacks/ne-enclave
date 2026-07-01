// SPDX-FileCopyrightText: 2026 Infrastacks LLC
// SPDX-License-Identifier: Apache-2.0

//! Raw and summary CSV writers for benchmark results.
//!
//! No external CSV dependency: all fields are numbers or simple
//! identifiers. We reject any field containing a comma, quote, or
//! newline so the hand-rolled writer can never produce malformed CSV.

use std::io::Write;

use crate::stats::Summary;

/// Error writing CSV output.
#[derive(Debug, thiserror::Error)]
pub enum CsvError {
    /// A field contained a character that would corrupt the CSV.
    #[error("field {field:?} contains an unsupported character (comma, quote, or newline)")]
    UnsafeField {
        /// The offending field value.
        field: String,
    },
    /// Row column count did not match the header.
    #[error("row has {got} columns, header has {want}")]
    ColumnMismatch {
        /// Header column count.
        want: usize,
        /// Row column count.
        got: usize,
    },
    /// Underlying I/O failure.
    #[error("csv io: {0}")]
    Io(#[from] std::io::Error),
}

fn check_field(field: &str) -> Result<(), CsvError> {
    if field.contains([',', '"', '\n']) {
        return Err(CsvError::UnsafeField {
            field: field.to_string(),
        });
    }
    Ok(())
}

fn write_row<W: Write>(w: &mut W, fields: &[String]) -> Result<(), CsvError> {
    for f in fields {
        check_field(f)?;
    }
    writeln!(w, "{}", fields.join(","))?;
    Ok(())
}

/// Streams raw per-trial rows under a fixed header.
pub struct RawWriter<W: Write> {
    writer: W,
    columns: usize,
}

impl<W: Write> RawWriter<W> {
    /// Create a writer and emit the header line.
    pub fn new(mut writer: W, header: &[&str]) -> Result<Self, CsvError> {
        let header_owned: Vec<String> = header.iter().map(|s| (*s).to_string()).collect();
        write_row(&mut writer, &header_owned)?;
        Ok(Self {
            writer,
            columns: header.len(),
        })
    }

    /// Append one data row. Length must match the header.
    pub fn row(&mut self, fields: &[String]) -> Result<(), CsvError> {
        if fields.len() != self.columns {
            return Err(CsvError::ColumnMismatch {
                want: self.columns,
                got: fields.len(),
            });
        }
        write_row(&mut self.writer, fields)
    }

    /// Flush the underlying writer.
    pub fn flush(&mut self) -> Result<(), CsvError> {
        self.writer.flush()?;
        Ok(())
    }
}

/// Write a single summary CSV (header + one row) for a labeled benchmark.
pub fn write_summary<W: Write>(mut w: W, label: &str, s: &Summary) -> Result<(), CsvError> {
    let header = [
        "benchmark",
        "n",
        "min_ms",
        "max_ms",
        "mean_ms",
        "stddev_ms",
        "p50_ms",
        "p90_ms",
        "p95_ms",
        "p99_ms",
    ];
    let header_owned: Vec<String> = header.iter().map(|h| (*h).to_string()).collect();
    write_row(&mut w, &header_owned)?;
    let row = vec![
        label.to_string(),
        s.n.to_string(),
        format!("{:.3}", s.min_ms),
        format!("{:.3}", s.max_ms),
        format!("{:.3}", s.mean_ms),
        format!("{:.3}", s.stddev_ms),
        format!("{:.3}", s.p50_ms),
        format!("{:.3}", s.p90_ms),
        format!("{:.3}", s.p95_ms),
        format!("{:.3}", s.p99_ms),
    ];
    write_row(&mut w, &row)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::stats::summarize;

    #[test]
    fn raw_writer_emits_header_and_rows() {
        let mut buf = Vec::new();
        {
            let mut w = RawWriter::new(&mut buf, &["trial", "ready_ms"]).unwrap();
            w.row(&["0".to_string(), "12.500".to_string()]).unwrap();
            w.row(&["1".to_string(), "13.000".to_string()]).unwrap();
            w.flush().unwrap();
        }
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out, "trial,ready_ms\n0,12.500\n1,13.000\n");
    }

    #[test]
    fn raw_writer_rejects_column_mismatch() {
        let mut buf = Vec::new();
        let mut w = RawWriter::new(&mut buf, &["a", "b"]).unwrap();
        let err = w.row(&["only-one".to_string()]).unwrap_err();
        assert!(matches!(err, CsvError::ColumnMismatch { want: 2, got: 1 }));
    }

    #[test]
    fn rejects_unsafe_field() {
        let mut buf = Vec::new();
        let mut w = RawWriter::new(&mut buf, &["a"]).unwrap();
        let err = w.row(&["has,comma".to_string()]).unwrap_err();
        assert!(matches!(err, CsvError::UnsafeField { .. }));
    }

    #[test]
    fn summary_round_trips_through_header() {
        let s = summarize(&[1.0, 2.0, 3.0]).unwrap();
        let mut buf = Vec::new();
        write_summary(&mut buf, "exec", &s).unwrap();
        let out = String::from_utf8(buf).unwrap();
        let lines: Vec<&str> = out.lines().collect();
        assert_eq!(lines.len(), 2);
        assert!(lines[0].starts_with("benchmark,n,min_ms"));
        assert!(lines[1].starts_with("exec,3,"));
    }
}
