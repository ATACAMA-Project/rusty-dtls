use core::{marker::PhantomData, ops::Range};

use aes_gcm::aead::Buffer;

use crate::DtlsError;

pub trait ConstSize {
    const STATIC_SIZE: usize;
    fn new() -> Self;
}

pub trait DynSize: Sized {
    const STATIC_SIZE: usize;
    fn new(num: usize) -> Result<Self, DtlsError>;
}

pub trait Slice<'a>: Sized {
    const STATIC_SIZE: usize;
    fn new(slice: &'a [u8]) -> Self;
}

impl ConstSize for () {
    const STATIC_SIZE: usize = 0;
    fn new() -> Self {}
}

/// Static size
pub struct S<const SIZE: usize, T = ()> {
    t: T,
}

impl<const SIZE: usize, T: ConstSize> ConstSize for S<SIZE, T> {
    const STATIC_SIZE: usize = SIZE + T::STATIC_SIZE;

    fn new() -> Self {
        Self { t: T::new() }
    }
}

impl<const SIZE: usize, T: DynSize> DynSize for S<SIZE, T> {
    const STATIC_SIZE: usize = SIZE + T::STATIC_SIZE;

    fn new(u: usize) -> Result<Self, DtlsError> {
        Ok(Self { t: T::new(u)? })
    }
}

impl<'a, const SIZE: usize, T: Slice<'a>> Slice<'a> for S<SIZE, T> {
    const STATIC_SIZE: usize = SIZE + T::STATIC_SIZE;

    fn new(slice: &'a [u8]) -> Self {
        Self { t: T::new(slice) }
    }
}

/// Dynamic size, which is determined at runtime.
/// Is used when reading slices.
pub struct D<T = ()> {
    len: usize,
    t: T,
}

impl<T: ConstSize> DynSize for D<T> {
    const STATIC_SIZE: usize = T::STATIC_SIZE;
    fn new(len: usize) -> Result<Self, DtlsError> {
        Ok(Self { len, t: T::new() })
    }
}

/// Iterator over a memory region with fixed stepsize `I`.
/// The length of the region gets passed at runtime.
pub struct Itr<I = (), T = ()> {
    len_left: usize,
    t: T,
    p: PhantomData<I>,
}

impl<I: ConstSize, T: ConstSize> DynSize for Itr<I, T> {
    const STATIC_SIZE: usize = T::STATIC_SIZE;
    fn new(mem_region_size: usize) -> Result<Self, DtlsError> {
        if mem_region_size % I::STATIC_SIZE == 0 {
            Ok(Self {
                len_left: mem_region_size,
                t: T::new(),
                p: PhantomData,
            })
        } else {
            Err(DtlsError::ParseError)
        }
    }
}

/// Write a dynamically sized slice which is passed at runtime
pub struct WriteSlice<'a, T = ()> {
    slice: &'a [u8],
    t: T,
}

impl<'a, T: ConstSize> Slice<'a> for WriteSlice<'a, T> {
    const STATIC_SIZE: usize = T::STATIC_SIZE;
    fn new(slice: &'a [u8]) -> Self {
        Self { slice, t: T::new() }
    }
}

pub struct Parser<'a, 'b, T = ()> {
    s: T,
    buf: &'a mut ParseBuffer<'b>,
}

impl Parser<'_, '_, ()> {
    pub fn read_single_u16(buf: &mut ParseBuffer<'_>) -> Result<u16, DtlsError> {
        if buf.offset + 2 > buf.buf.len() {
            Err(DtlsError::OutOfMemory)
        } else {
            Ok(buf.read_u16())
        }
    }
    pub fn read_single_u8(buf: &mut ParseBuffer<'_>) -> Result<u8, DtlsError> {
        if buf.offset + 1 > buf.buf.len() {
            Err(DtlsError::OutOfMemory)
        } else {
            Ok(buf.read_u8())
        }
    }
}

impl<'a, 'b, T: ConstSize> Parser<'a, 'b, T> {
    /// Creates a parser which only parses chunks of sizes known at compile time.
    pub fn new(buf: &'a mut ParseBuffer<'b>) -> Result<Self, DtlsError> {
        let e = T::STATIC_SIZE;
        if e + buf.offset > buf.buf.len() {
            Err(DtlsError::OutOfMemory)
        } else {
            Ok(Self { s: T::new(), buf })
        }
    }
}

impl<'a, 'b, T: DynSize> Parser<'a, 'b, T> {
    /// Creates a parser that can parse *one* chunk of dynamic size.
    pub fn new_dyn(buf: &'a mut ParseBuffer<'b>, dyn_size: usize) -> Result<Self, DtlsError> {
        let t = T::new(dyn_size)?;
        if T::STATIC_SIZE + dyn_size <= buf.buf.len() {
            Ok(Self { s: t, buf })
        } else {
            Err(DtlsError::OutOfMemory)
        }
    }
}

impl<'a, 'b, T: Slice<'a>> Parser<'a, 'b, T> {
    /// Creates a parser that can write *one* slice of dynamic size.
    pub fn new_mut_slice(
        buf: &'a mut ParseBuffer<'b>,
        dyn_slice: &'a [u8],
    ) -> Result<Self, DtlsError> {
        if T::STATIC_SIZE + dyn_slice.len() <= buf.buf.len() {
            let t = T::new(dyn_slice);
            Ok(Self { s: t, buf })
        } else {
            Err(DtlsError::OutOfMemory)
        }
    }
}

macro_rules! static_rw_impl {
    ($read:ident,$write:ident,$size:expr,$tr:ty, $tw: ty) => {
        impl<'a, 'b, T> Parser<'a, 'b, S<$size, T>> {
            pub fn $read(self) -> ($tr, Parser<'a, 'b, T>) {
                (self.buf.$read(), self.unpack())
            }
            pub fn $write(self, val: $tw) -> Parser<'a, 'b, T> {
                self.buf.$write(val);
                self.unpack()
            }
        }
    };
}
static_rw_impl!(read_u8, write_u8, 1, u8, u8);
static_rw_impl!(read_u16, write_u16, 2, u16, u16);
static_rw_impl!(read_u24, write_u24, 3, u32, u32);
static_rw_impl!(read_u32, write_u32, 4, u32, u32);
static_rw_impl!(read_u48, write_u48, 6, u64, &u64);
static_rw_impl!(read_u64, write_u64, 8, u64, &u64);

impl<'a, 'b, T> Parser<'a, 'b, D<T>> {
    pub fn read_slice(&mut self) -> &mut [u8] {
        self.buf.offset += self.s.len;
        &mut self.buf.buf[self.buf.offset - self.s.len..self.buf.offset]
    }

    pub fn done(self) -> Parser<'a, 'b, T> {
        Parser::<'a, 'b, T> {
            s: self.s.t,
            buf: self.buf,
        }
    }
}

impl<'a, 'b, T> Parser<'a, 'b, WriteSlice<'a, T>> {
    pub fn write_len_u8(self) -> Self {
        self.buf.write_u8(self.s.slice.len() as u8);
        self
    }

    pub fn write_len_u16(self) -> Self {
        self.buf.write_u16(self.s.slice.len() as u16);
        self
    }

    /// Writes the dynamic slice captured in the parser
    pub fn write_slice(self) -> Parser<'a, 'b, T> {
        self.buf.write_slice(self.s.slice);
        Parser::<'a, 'b, T> {
            s: self.s.t,
            buf: self.buf,
        }
    }
}

impl<'a, 'b, const SIZE: usize, T> Parser<'a, 'b, S<SIZE, T>> {
    pub fn add_offset(self) -> Parser<'a, 'b, T> {
        self.buf.offset += SIZE;
        self.unpack()
    }

    pub fn read_static_slice(&mut self) -> &mut [u8; SIZE] {
        self.buf.offset += SIZE;
        (&mut self.buf.buf[self.buf.offset - SIZE..self.buf.offset])
            .try_into()
            .unwrap()
    }

    pub fn done(self) -> Parser<'a, 'b, T> {
        self.unpack()
    }

    pub fn write_static_slice(self, val: &[u8; SIZE]) -> Parser<'a, 'b, T> {
        self.buf.write_slice(val);
        self.unpack()
    }

    fn unpack(self) -> Parser<'a, 'b, T> {
        Parser::<'a, 'b, T> {
            s: self.s.t,
            buf: self.buf,
        }
    }
}
impl<'a, 'b, I: ConstSize, T> Parser<'a, 'b, Itr<I, T>> {
    pub fn next<'c>(&'c mut self) -> Option<Parser<'c, 'b, I>> {
        if self.s.len_left == 0 {
            None
        } else {
            self.s.len_left -= I::STATIC_SIZE;
            Some(Parser {
                s: I::new(),
                buf: self.buf,
            })
        }
    }

    pub fn done(self) -> Parser<'a, 'b, T> {
        Parser::<'a, 'b, T> {
            s: self.s.t,
            buf: self.buf,
        }
    }
}

impl Parser<'_, '_, ()> {
    pub fn end(self) {}
}

pub struct ParseBuffer<'a> {
    buf: &'a mut [u8],
    offset: usize,
}

impl<'a> ParseBuffer<'a> {
    pub fn init(buf: &'a mut [u8]) -> Self {
        ParseBuffer { buf, offset: 0 }
    }

    pub fn init_with_offset(buf: &'a mut [u8], offset: usize) -> Self {
        debug_assert!(buf.len() >= offset);
        ParseBuffer { buf, offset }
    }

    pub fn with_offset(&mut self, offset: usize) -> ParseBuffer<'_> {
        debug_assert!(self.buf.len() >= offset);
        ParseBuffer {
            buf: self.buf,
            offset,
        }
    }

    fn read_u8(&mut self) -> u8 {
        self.offset += 1;
        self.buf[self.offset - 1]
    }

    fn read_u16(&mut self) -> u16 {
        self.offset += 2;
        u16::from_be_bytes(self.buf[self.offset - 2..self.offset].try_into().unwrap())
    }

    fn read_u24(&mut self) -> u32 {
        self.offset += 3;
        let mut num = [0; 4];
        num[1..4].copy_from_slice(&self.buf[self.offset - 3..self.offset]);
        u32::from_be_bytes(num)
    }

    fn read_u32(&mut self) -> u32 {
        self.offset += 4;
        u32::from_be_bytes(self.buf[self.offset - 4..self.offset].try_into().unwrap())
    }

    fn read_u48(&mut self) -> u64 {
        self.offset += 6;
        let mut num = [0; 8];
        num[2..8].copy_from_slice(&self.buf[self.offset - 6..self.offset]);
        u64::from_be_bytes(num)
    }

    fn read_u64(&mut self) -> u64 {
        self.offset += 8;
        u64::from_be_bytes(self.buf[self.offset - 8..self.offset].try_into().unwrap())
    }

    pub fn read_slice_checked(&mut self, len: usize) -> Result<&[u8], DtlsError> {
        if len + self.offset > self.buf.len() {
            Err(DtlsError::OutOfMemory)
        } else {
            self.offset += len;
            Ok(&self.buf[self.offset - len..self.offset])
        }
    }

    fn write_u8(&mut self, val: u8) {
        self.offset += 1;
        self.buf[self.offset - 1] = val
    }

    fn write_u16(&mut self, val: u16) {
        self.offset += 2;
        self.buf[self.offset - 2..self.offset].copy_from_slice(&val.to_be_bytes());
    }

    fn write_u24(&mut self, val: u32) {
        self.offset += 3;
        self.buf[self.offset - 3..self.offset].copy_from_slice(&val.to_be_bytes()[1..4]);
    }

    fn write_u32(&mut self, val: u32) {
        self.offset += 4;
        self.buf[self.offset - 4..self.offset].copy_from_slice(&val.to_be_bytes());
    }

    fn write_u48(&mut self, val: &u64) {
        self.offset += 6;
        self.buf[self.offset - 6..self.offset].copy_from_slice(&val.to_be_bytes()[2..8]);
    }

    fn write_u64(&mut self, val: &u64) {
        self.offset += 8;
        self.buf[self.offset - 8..self.offset].copy_from_slice(&val.to_be_bytes());
    }

    pub fn write_slice_checked(&mut self, slice: &[u8]) -> Result<(), DtlsError> {
        if slice.len() + self.offset > self.buf.len() {
            Err(DtlsError::OutOfMemory)
        } else {
            self.write_slice(slice);
            Ok(())
        }
    }

    fn write_slice(&mut self, slice: &[u8]) {
        self.offset += slice.len();
        self.buf[self.offset - slice.len()..self.offset].copy_from_slice(slice);
    }

    /// Does not affect buffer offset.
    pub fn access_slice_checked(&self, r: Range<usize>) -> Result<&[u8], DtlsError> {
        if r.end > self.buf.len() {
            Err(DtlsError::OutOfMemory)
        } else {
            Ok(&self.buf[r])
        }
    }

    /// Splits the whole underlying buffer regardless of an offset
    pub fn split_at_mut_checked(
        &mut self,
        pos: usize,
    ) -> Result<(&mut [u8], &mut [u8]), DtlsError> {
        if pos > self.buf.len() {
            Err(DtlsError::OutOfMemory)
        } else {
            Ok(self.buf.split_at_mut(pos))
        }
    }

    pub fn release_buffer(self) -> &'a mut [u8] {
        self.buf
    }

    #[cfg(test)]
    pub fn complete_inner_buffer(&self) -> &[u8] {
        self.buf
    }

    pub fn write_prepend_length_u16(
        &mut self,
        variable_content: &mut dyn FnMut(&mut Self) -> Result<(), DtlsError>,
    ) -> Result<usize, DtlsError> {
        self.write_prepend_length(2, variable_content)
    }

    fn write_prepend_length(
        &mut self,
        len: usize,
        variable_content: &mut dyn FnMut(&mut Self) -> Result<(), DtlsError>,
    ) -> Result<usize, DtlsError> {
        let offset_begin = self.offset;
        self.expect_length(len)?;
        self.offset += len;
        variable_content(self)?;
        let length = self.offset - offset_begin - len;
        if length > 2 << (len * 8) {
            return Err(DtlsError::ParseError);
        }
        self.buf[offset_begin..offset_begin + len]
            .copy_from_slice(&(length as u16).to_be_bytes()[..len]);
        Ok(length)
    }

    /// Increases offset but does not write anything.
    pub fn add_offset(&mut self, len: usize) {
        debug_assert!(self.buf.len() >= len + self.offset);
        self.offset += len;
    }

    pub fn set_offset(&mut self, offset: usize) {
        debug_assert!(offset < self.buf.len());
        self.offset = offset;
    }

    pub fn offset(&self) -> usize {
        self.offset
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }

    pub fn expect_length(&self, len: usize) -> Result<(), DtlsError> {
        if self.buf.len() - self.offset >= len {
            Ok(())
        } else {
            Err(DtlsError::OutOfMemory)
        }
    }

    pub fn truncate(&mut self, len: usize) {
        let offset = self.offset;
        let buf = core::mem::take(&mut self.buf);
        *self = ParseBuffer::init_with_offset(&mut buf[..len], offset);
    }
}

impl AsMut<[u8]> for ParseBuffer<'_> {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.offset]
    }
}

impl AsRef<[u8]> for ParseBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        &self.buf[..self.offset]
    }
}

impl Buffer for ParseBuffer<'_> {
    fn extend_from_slice(&mut self, other: &[u8]) -> aes_gcm::aead::Result<()> {
        self.write_slice_checked(other)
            .map_err(|_| aes_gcm::aead::Error {})
    }

    fn truncate(&mut self, len: usize) {
        self.offset = len;
    }
}

pub fn parse_expect(expect: bool, err: DtlsError) -> Result<(), DtlsError> {
    if expect {
        Ok(())
    } else {
        Err(err)
    }
}
