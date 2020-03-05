/* -*- Mode: rust; rust-indent-offset: 4 -*- */
/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

use byteorder::{BigEndian, NativeEndian, ReadBytesExt, WriteBytesExt};
use std::convert::TryInto;
use std::fmt;

/// Accessing fields of packed structs is unsafe (it may be undefined behavior if the field isn't
/// aligned). Since we're implementing a PKCS#11 module, we already have to trust the caller not to
/// give us bad data, so normally we would deal with this by adding an unsafe block. If we do that,
/// though, the compiler complains that the unsafe block is unnecessary. Thus, we use this macro to
/// annotate the unsafe block to silence the compiler.
macro_rules! unsafe_packed_field_access {
    ($e:expr) => {{
        #[allow(unused_unsafe)]
        let tmp = unsafe { $e };
        tmp
    }};
}

#[cfg(target_os = "macos")]
pub const OID_BYTES_SECP256R1: &[u8] =
    &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
#[cfg(target_os = "macos")]
pub const OID_BYTES_SECP384R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
#[cfg(target_os = "macos")]
pub const OID_BYTES_SECP521R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23];

pub enum TracingErrorType {
    Base(String),
    Stack(Box<TracingError>),
}

pub struct TracingError {
    location: String,
    next: TracingErrorType,
}

impl TracingError {
    pub fn new(location: String, next: TracingErrorType) -> TracingError {
        TracingError { location, next }
    }
}

impl fmt::Display for TracingError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.location)?;
        match &self.next {
            TracingErrorType::Base(msg) => write!(f, ": {}", msg),
            TracingErrorType::Stack(next) => write!(f, ": {}", next),
        }
    }
}

macro_rules! trace_error_stack {
    ($next:ident) => {
        TracingError::new(
            format!("{}:{}", file!(), line!()),
            TracingErrorType::Stack(Box::new($next)),
        )
    };
}

macro_rules! trace_error {
    ($msg:expr) => {
        TracingError::new(
            format!("{}:{}", file!(), line!()),
            TracingErrorType::Base($msg),
        )
    };
}

// This is a helper function to take a value and lay it out in memory how
// PKCS#11 is expecting it.
pub fn serialize_uint<T: TryInto<u64> + fmt::Display + Copy>(
    value: T,
) -> Result<Vec<u8>, TracingError> {
    let value_size = std::mem::size_of::<T>();
    let mut value_buf = Vec::with_capacity(value_size);
    let value_as_u64 = value
        .try_into()
        .map_err(|_| trace_error!(format!("couldn't convert {} to u64", value)))?;
    value_buf
        .write_uint::<NativeEndian>(value_as_u64, value_size)
        .map_err(|e| trace_error!(e.to_string()))?;
    Ok(value_buf)
}

/// Given a slice of DER bytes representing an RSA public key, extracts the bytes of the modulus
/// as an unsigned integer. Also verifies that the public exponent is present (again as an
/// unsigned integer). Finally verifies that reading these values consumes the entirety of the
/// slice.
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
pub fn read_rsa_modulus(public_key: &[u8]) -> Result<Vec<u8>, TracingError> {
    let mut sequence = Sequence::new(public_key).map_err(|e| trace_error_stack!(e))?;
    let modulus_value = sequence
        .read_unsigned_integer()
        .map_err(|e| trace_error_stack!(e))?;
    let _exponent = sequence
        .read_unsigned_integer()
        .map_err(|e| trace_error_stack!(e))?;
    if !sequence.at_end() {
        return Err(trace_error!(
            "unexpected trailing data after public key".to_string()
        ));
    }
    Ok(modulus_value.to_vec())
}

/// Given a slice of DER bytes representing an ECDSA signature, extracts the bytes of `r` and `s`
/// as unsigned integers. Also verifies that this consumes the entirety of the slice.
///   Ecdsa-Sig-Value  ::=  SEQUENCE  {
///        r     INTEGER,
///        s     INTEGER  }
#[cfg(target_os = "macos")]
pub fn read_ec_sig_point<'a>(signature: &'a [u8]) -> Result<(&'a [u8], &'a [u8]), TracingError> {
    let mut sequence = Sequence::new(signature).map_err(|e| trace_error_stack!(e))?;
    let r = sequence
        .read_unsigned_integer()
        .map_err(|e| trace_error_stack!(e))?;
    let s = sequence
        .read_unsigned_integer()
        .map_err(|e| trace_error_stack!(e))?;
    if !sequence.at_end() {
        return Err(trace_error!(
            "unexpected trailing data after ec signature".to_string()
        ));
    }
    Ok((r, s))
}

/// Helper macro for reading some bytes from a slice while checking the slice is long enough.
/// Returns a pair consisting of a slice of the bytes read and a slice of the rest of the bytes
/// from the original slice.
macro_rules! try_read_bytes {
    ($data:ident, $len:expr) => {{
        if $data.len() < $len {
            return Err(trace_error!("input truncated".to_string()));
        }
        $data.split_at($len)
    }};
}

/// ASN.1 tag identifying an integer.
const INTEGER: u8 = 0x02;
/// ASN.1 tag identifying a sequence.
const SEQUENCE: u8 = 0x10;
/// ASN.1 tag modifier identifying an item as constructed.
const CONSTRUCTED: u8 = 0x20;

/// A helper struct for reading items from a DER SEQUENCE (in this case, all sequences are
/// assumed to be CONSTRUCTED).
struct Sequence<'a> {
    /// The contents of the SEQUENCE.
    contents: Der<'a>,
}

impl<'a> Sequence<'a> {
    fn new(input: &'a [u8]) -> Result<Sequence<'a>, TracingError> {
        let mut der = Der::new(input);
        let sequence_bytes = der
            .read(SEQUENCE | CONSTRUCTED)
            .map_err(|e| trace_error_stack!(e))?;
        // We're assuming we want to consume the entire input for now.
        if !der.at_end() {
            return Err(trace_error!(
                "unexpected trailing data after SEQUENCE".to_string()
            ));
        }
        Ok(Sequence {
            contents: Der::new(sequence_bytes),
        })
    }

    // TODO: we're not exhaustively validating this integer
    fn read_unsigned_integer(&mut self) -> Result<&'a [u8], TracingError> {
        let bytes = self
            .contents
            .read(INTEGER)
            .map_err(|e| trace_error_stack!(e))?;
        if bytes.is_empty() {
            return Err(trace_error!("empty INTEGER?".to_string()));
        }
        // There may be a leading zero (we should also check that the first bit
        // of the rest of the integer is set).
        if bytes[0] == 0 && bytes.len() > 1 {
            let (_, integer) = bytes.split_at(1);
            Ok(integer)
        } else {
            Ok(bytes)
        }
    }

    fn at_end(&self) -> bool {
        self.contents.at_end()
    }
}

/// A helper struct for reading DER data. The contents are treated like a cursor, so its position
/// is updated as data is read.
struct Der<'a> {
    contents: &'a [u8],
}

impl<'a> Der<'a> {
    fn new(contents: &'a [u8]) -> Der<'a> {
        Der { contents }
    }

    // In theory, a caller could encounter an error and try another operation, in which case we may
    // be in an inconsistent state. As long as this implementation isn't exposed to code that would
    // use it incorrectly (i.e. it stays in this module and we only expose a stateless API), it
    // should be safe.
    fn read(&mut self, tag: u8) -> Result<&'a [u8], TracingError> {
        let contents = self.contents;
        let (tag_read, rest) = try_read_bytes!(contents, 1);
        if tag_read[0] != tag {
            return Err(trace_error!(format!(
                "expected tag {}, got {}",
                tag, tag_read[0]
            )));
        }
        let (length1, rest) = try_read_bytes!(rest, 1);
        let (length, to_read_from) = if length1[0] < 0x80 {
            (length1[0] as usize, rest)
        } else if length1[0] == 0x81 {
            let (length, rest) = try_read_bytes!(rest, 1);
            if length[0] < 0x80 {
                return Err(trace_error!(format!(
                    "length of {} not in shortest form",
                    length[0]
                )));
            }
            (length[0] as usize, rest)
        } else if length1[0] == 0x82 {
            let (lengths, rest) = try_read_bytes!(rest, 2);
            let length = (&mut &lengths[..])
                .read_u16::<BigEndian>()
                .map_err(|_| trace_error!("couldn't read u16 from 2-byte slice?".to_string()))?;
            if length < 256 {
                return Err(trace_error!(format!(
                    "length of {} not in shortest form",
                    length
                )));
            }
            (length as usize, rest)
        } else {
            return Err(trace_error!(
                "DER longer than 65535 bytes not supported".to_string()
            ));
        };
        let (contents, rest) = try_read_bytes!(to_read_from, length);
        self.contents = rest;
        Ok(contents)
    }

    fn at_end(&self) -> bool {
        self.contents.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn der_test_empty_input() {
        let input = Vec::new();
        let mut der = Der::new(&input);
        assert!(der.read(INTEGER).is_err());
    }

    #[test]
    fn der_test_no_length() {
        let input = vec![INTEGER];
        let mut der = Der::new(&input);
        assert!(der.read(INTEGER).is_err());
    }

    #[test]
    fn der_test_empty_sequence() {
        let input = vec![SEQUENCE, 0];
        let mut der = Der::new(&input);
        let read_result = der.read(SEQUENCE);
        assert!(read_result.is_ok());
        let sequence_bytes = read_result.unwrap();
        assert_eq!(sequence_bytes.len(), 0);
        assert!(der.at_end());
    }

    #[test]
    fn der_test_not_at_end() {
        let input = vec![SEQUENCE, 0, 1];
        let mut der = Der::new(&input);
        let read_result = der.read(SEQUENCE);
        assert!(read_result.is_ok());
        let sequence_bytes = read_result.unwrap();
        assert_eq!(sequence_bytes.len(), 0);
        assert!(!der.at_end());
    }

    #[test]
    fn der_test_wrong_tag() {
        let input = vec![SEQUENCE, 0];
        let mut der = Der::new(&input);
        assert!(der.read(INTEGER).is_err());
    }

    #[test]
    fn der_test_truncated_two_byte_length() {
        let input = vec![SEQUENCE, 0x81];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_truncated_three_byte_length() {
        let input = vec![SEQUENCE, 0x82, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_truncated_data() {
        let input = vec![SEQUENCE, 20, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_sequence() {
        let input = vec![
            SEQUENCE, 20, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 0, 0,
        ];
        let mut der = Der::new(&input);
        let result = der.read(SEQUENCE);
        assert!(result.is_ok());
        assert_eq!(
            result.unwrap(),
            [1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 0, 0]
        );
        assert!(der.at_end());
    }

    #[test]
    fn der_test_not_shortest_two_byte_length_encoding() {
        let input = vec![SEQUENCE, 0x81, 1, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_not_shortest_three_byte_length_encoding() {
        let input = vec![SEQUENCE, 0x82, 0, 1, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_indefinite_length_unsupported() {
        let input = vec![SEQUENCE, 0x80, 1, 2, 3, 0x00, 0x00];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn der_test_input_too_long() {
        // This isn't valid DER (the contents of the SEQUENCE are truncated), but it demonstrates
        // that we don't try to read too much if we're given a long length (and also that we don't
        // support lengths 2^16 and up).
        let input = vec![SEQUENCE, 0x83, 0x01, 0x00, 0x01, 1, 1, 1, 1];
        let mut der = Der::new(&input);
        assert!(der.read(SEQUENCE).is_err());
    }

    #[test]
    fn empty_input_fails() {
        let empty = Vec::new();
        assert!(read_rsa_modulus(&empty).is_err());
        assert!(read_ec_sig_point(&empty).is_err());
    }

    #[test]
    fn empty_sequence_fails() {
        let empty = vec![SEQUENCE | CONSTRUCTED];
        assert!(read_rsa_modulus(&empty).is_err());
        assert!(read_ec_sig_point(&empty).is_err());
    }

    #[test]
    fn test_read_rsa_modulus() {
        let rsa_key = include_bytes!("../test/rsa.bin");
        let result = read_rsa_modulus(rsa_key);
        assert!(result.is_ok());
        let modulus = result.unwrap();
        assert_eq!(modulus, include_bytes!("../test/modulus.bin").to_vec());
    }
}
