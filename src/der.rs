use byteorder::{BigEndian, ReadBytesExt};

macro_rules! try_read_bytes {
    ($data:ident, $len:expr) => {{
        if $data.len() < $len {
            return Err(());
        }
        $data.split_at($len)
    }};
}

const INTEGER: u8 = 0x02;
const SEQUENCE: u8 = 0x10;
const CONSTRUCTED: u8 = 0x20;

pub struct Sequence<'a> {
    contents: Der<'a>,
}

impl<'a> Sequence<'a> {
    pub fn new(input: &'a [u8]) -> Result<Sequence<'a>, ()> {
        let mut der = Der::new(input);
        let sequence_bytes = der.read(SEQUENCE | CONSTRUCTED)?;
        // We're assuming we want to consume the entire input for now.
        if !der.at_end() {
            return Err(());
        }
        Ok(Sequence {
            contents: Der::new(sequence_bytes),
        })
    }

    // TODO: we're not exhaustively validating this integer
    pub fn read_unsigned_integer(&mut self) -> Result<&'a [u8], ()> {
        let bytes = self.contents.read(INTEGER)?;
        if bytes.len() < 1 {
            return Err(());
        }
        // There may be a leading zero (we should also check that the first bit
        // of the rest of the integer is set).
        if bytes[0] == 0 {
            let (_, integer) = bytes.split_at(1);
            Ok(integer)
        } else {
            Ok(bytes)
        }
    }

    pub fn at_end(&self) -> bool {
        self.contents.at_end()
    }
}

struct Der<'a> {
    contents: &'a [u8],
}

impl<'a> Der<'a> {
    pub fn new(contents: &'a [u8]) -> Der<'a> {
        Der { contents }
    }

    // TODO: in theory, a caller could encounter an error and try again, in
    // which case we may be in an inconsistent state.
    fn read(&mut self, tag: u8) -> Result<&'a [u8], ()> {
        let contents = self.contents;
        let (tag_read, rest) = try_read_bytes!(contents, 1);
        if tag_read[0] != tag {
            return Err(());
        }
        let (length1, rest) = try_read_bytes!(rest, 1);
        let (length, to_read_from) = if length1[0] < 0x80 {
            (length1[0] as usize, rest)
        } else if length1[0] == 0x81 {
            let (length, rest) = try_read_bytes!(rest, 1);
            if length[0] < 0x80 {
                return Err(());
            }
            (length[0] as usize, rest)
        } else if length1[0] == 0x82 {
            let (lengths, rest) = try_read_bytes!(rest, 2);
            let length = (&mut &lengths[..])
                .read_u16::<BigEndian>()
                .map_err(|_| ())?;
            if length < 256 {
                return Err(());
            }
            (length as usize, rest)
        } else {
            return Err(());
        };
        let (contents, rest) = try_read_bytes!(to_read_from, length);
        self.contents = rest;
        Ok(contents)
    }

    fn at_end(&self) -> bool {
        self.contents.is_empty()
    }
}
