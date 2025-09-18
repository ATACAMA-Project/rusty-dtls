use core::{marker::PhantomData, ops::Range};

use aes_gcm::aead::Buffer;

use crate::DtlsError;

pub trait InitConst {
    const STATIC_SIZE: usize;
    fn new() -> Self;
}

pub trait InitDyn: Sized {
    const STATIC_SIZE: usize;
    fn new(len: usize) -> Result<Self, DtlsError>;
}

pub trait InitSlice<'a>: Sized {
    const STATIC_SIZE: usize;
    fn new(slice: &'a [u8]) -> Self;
}

impl InitConst for () {
    const STATIC_SIZE: usize = 0;
    fn new() -> Self {}
}

/// Const size
pub struct C<const SIZE: usize, T = ()> {
    t: T,
}

impl<const SIZE: usize, T: InitConst> InitConst for C<SIZE, T> {
    const STATIC_SIZE: usize = SIZE + T::STATIC_SIZE;

    fn new() -> Self {
        Self { t: T::new() }
    }
}

impl<const SIZE: usize, T: InitDyn> InitDyn for C<SIZE, T> {
    const STATIC_SIZE: usize = SIZE + T::STATIC_SIZE;

    fn new(len: usize) -> Result<Self, DtlsError> {
        Ok(Self { t: T::new(len)? })
    }
}

impl<'a, const SIZE: usize, T: InitSlice<'a>> InitSlice<'a> for C<SIZE, T> {
    const STATIC_SIZE: usize = SIZE + T::STATIC_SIZE;

    fn new(slice: &'a [u8]) -> Self {
        Self { t: T::new(slice) }
    }
}

/// Access constant slice
pub struct AccessConstSlice<const SIZE: usize, T = ()> {
    t: T,
}

impl<const SIZE: usize, T: InitConst> InitConst for AccessConstSlice<SIZE, T> {
    const STATIC_SIZE: usize = SIZE + T::STATIC_SIZE;
    fn new() -> Self {
        Self { t: T::new() }
    }
}

impl<const SIZE: usize, T: InitDyn> InitDyn for AccessConstSlice<SIZE, T> {
    const STATIC_SIZE: usize = SIZE + T::STATIC_SIZE;
    fn new(len: usize) -> Result<Self, DtlsError> {
        Ok(Self { t: T::new(len)? })
    }
}

impl<'a, const SIZE: usize, T: InitSlice<'a>> InitSlice<'a> for AccessConstSlice<SIZE, T> {
    const STATIC_SIZE: usize = SIZE + T::STATIC_SIZE;
    fn new(slice: &'a [u8]) -> Self {
        Self { t: T::new(slice) }
    }
}

/// Access dynamic slice
pub struct AccessDynSlice<T = ()> {
    len: usize,
    t: T,
}

impl<T: InitConst> InitDyn for AccessDynSlice<T> {
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

impl<I: InitConst, T: InitConst> InitDyn for Itr<I, T> {
    const STATIC_SIZE: usize = T::STATIC_SIZE;
    fn new(mem_region_size: usize) -> Result<Self, DtlsError> {
        if mem_region_size.is_multiple_of(I::STATIC_SIZE) {
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
pub struct WriteSlice<'a, const LEN_S: usize, T = ()> {
    slice: &'a [u8],
    t: T,
}

impl<'a, const LEN_S: usize, T: InitConst> InitSlice<'a> for WriteSlice<'a, LEN_S, T> {
    const STATIC_SIZE: usize = T::STATIC_SIZE + LEN_S;
    fn new(slice: &'a [u8]) -> Self {
        Self { slice, t: T::new() }
    }
}

pub struct Parser<'a, 'b, T = ()> {
    s: T,
    buf: &'a mut ParseBuffer<'b>,
}

impl Parser<'_, '_, ()> {
    pub fn read_single_u8(buf: &mut ParseBuffer<'_>) -> Result<u8, DtlsError> {
        if buf.offset + 1 > buf.buf.len() {
            Err(DtlsError::OutOfMemory)
        } else {
            Ok(buf.read_u8())
        }
    }
    pub fn read_single_u16(buf: &mut ParseBuffer<'_>) -> Result<u16, DtlsError> {
        if buf.offset + 2 > buf.buf.len() {
            Err(DtlsError::OutOfMemory)
        } else {
            Ok(buf.read_u16())
        }
    }
}

impl<'a, 'b, T: InitConst> Parser<'a, 'b, T> {
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

impl<'a, 'b, T: InitDyn> Parser<'a, 'b, T> {
    /// Creates a parser that can parse *one* chunk of dynamic size.
    /// This can be done as the whole slice or as an iterator using `next`.
    pub fn new_dyn(buf: &'a mut ParseBuffer<'b>, dyn_size: usize) -> Result<Self, DtlsError> {
        let t = T::new(dyn_size)?;
        if T::STATIC_SIZE + dyn_size <= buf.buf.len() {
            Ok(Self { s: t, buf })
        } else {
            Err(DtlsError::OutOfMemory)
        }
    }
}

impl<'a, 'b, T: InitSlice<'a>> Parser<'a, 'b, T> {
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
        impl<'a, 'b, T> Parser<'a, 'b, C<$size, T>> {
            #[inline(always)]
            pub fn $read(self) -> ($tr, Parser<'a, 'b, T>) {
                (self.buf.$read(), self.unpack())
            }
            #[inline(always)]
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

impl<'a, 'b, const SIZE: usize, T> Parser<'a, 'b, C<0, AccessConstSlice<SIZE, T>>> {
    pub fn access_static_slice(self) -> Parser<'a, 'b, AccessConstSlice<SIZE, T>> {
        self.buf.offset += SIZE;
        Parser::<'a, 'b, AccessConstSlice<SIZE, T>> {
            s: self.s.t,
            buf: self.buf,
        }
    }
}

impl<'a, 'b, T> Parser<'a, 'b, C<0, AccessDynSlice<T>>> {
    pub fn access_dyn_slice(self) -> Parser<'a, 'b, AccessDynSlice<T>> {
        self.buf.offset += self.s.t.len;
        Parser::<'a, 'b, AccessDynSlice<T>> {
            s: self.s.t,
            buf: self.buf,
        }
    }
}

impl<'a, 'b, const SIZE: usize, T> Parser<'a, 'b, AccessConstSlice<SIZE, T>> {
    pub fn slice_mut(&mut self) -> &mut [u8; SIZE] {
        (&mut self.buf.buf[self.buf.offset - SIZE..self.buf.offset])
            .try_into()
            .unwrap()
    }

    pub fn done(self) -> Parser<'a, 'b, T> {
        Parser::<'a, 'b, T> {
            s: self.s.t,
            buf: self.buf,
        }
    }
}

impl<'a, 'b, T> Parser<'a, 'b, AccessDynSlice<T>> {
    pub fn slice(&self) -> &[u8] {
        &self.buf.buf[self.buf.offset - self.s.len..self.buf.offset]
    }

    pub fn done(self) -> Parser<'a, 'b, T> {
        Parser::<'a, 'b, T> {
            s: self.s.t,
            buf: self.buf,
        }
    }
}

impl<'a, 'b, const SIZE: usize, T> Parser<'a, 'b, C<SIZE, T>> {
    pub fn add_offset(self) -> Parser<'a, 'b, T> {
        self.buf.offset += SIZE;
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

impl<'a, 'b, I: InitConst, T> Parser<'a, 'b, C<2, Itr<I, T>>> {
    /// Writes the dynamic lenght as u16
    pub fn write_dyn_len_u16(self) -> Parser<'a, 'b, Itr<I, T>> {
        self.buf.write_u16(self.s.t.len_left as u16);
        self.unpack()
    }
}

impl<'a, 'b, I: InitConst, T> Parser<'a, 'b, Itr<I, T>> {
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

impl<'a, 'b, T> Parser<'a, 'b, WriteSlice<'a, 1, T>> {
    /// Writes the dynamic slice captured in the parser
    pub fn write_slice_with_u8_len(self) -> Parser<'a, 'b, T> {
        self.buf.write_u8(self.s.slice.len() as u8);
        self.buf.write_slice(self.s.slice);
        Parser::<'a, 'b, T> {
            s: self.s.t,
            buf: self.buf,
        }
    }
}

impl<'a, 'b, T> Parser<'a, 'b, WriteSlice<'a, 2, T>> {
    /// Writes the dynamic slice captured in the parser
    pub fn write_slice_with_u16_len(self) -> Parser<'a, 'b, T> {
        self.buf.write_u16(self.s.slice.len() as u16);
        self.buf.write_slice(self.s.slice);
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
        let o = self.offset.min(self.buf.len());
        u16::from_be_bytes(*self.buf[..o].split_last_chunk::<2>().unwrap().1)
    }

    fn read_u24(&mut self) -> u32 {
        self.offset += 3;
        let o = self.offset.min(self.buf.len());
        let mut num = [0; 4];
        num[1..4].copy_from_slice(self.buf[..o].split_last_chunk::<3>().unwrap().1);
        u32::from_be_bytes(num)
    }

    fn read_u32(&mut self) -> u32 {
        self.offset += 4;
        let o = self.offset.min(self.buf.len());
        u32::from_be_bytes(*self.buf[..o].split_last_chunk::<4>().unwrap().1)
    }

    fn read_u48(&mut self) -> u64 {
        self.offset += 6;
        let o = self.offset.min(self.buf.len());
        let mut num = [0; 8];
        num[2..8].copy_from_slice(self.buf[..o].split_last_chunk::<6>().unwrap().1);
        u64::from_be_bytes(num)
    }

    fn read_u64(&mut self) -> u64 {
        self.offset += 8;
        let o = self.offset.min(self.buf.len());
        u64::from_be_bytes(*self.buf[..o].split_last_chunk::<8>().unwrap().1)
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
        *self
            .buf
            .get_mut(..self.offset)
            .and_then(|b| b.split_last_chunk_mut::<2>())
            .unwrap()
            .1 = val.to_be_bytes();
    }

    fn write_u24(&mut self, val: u32) {
        self.offset += 3;
        *self
            .buf
            .get_mut(..self.offset)
            .and_then(|b| b.split_last_chunk_mut::<3>())
            .unwrap()
            .1 = val.to_be_bytes()[1..4].try_into().unwrap();
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
        *self
            .buf
            .get_mut(..self.offset)
            .and_then(|b| b.split_last_chunk_mut::<8>())
            .unwrap()
            .1 = val.to_be_bytes();
        // self.buf[self.offset - 8..self.offset].copy_from_slice(&val.to_be_bytes());
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
        self.buf.get(r).ok_or(DtlsError::OutOfMemory)
    }

    /// Does not affect buffer offset.
    pub fn access_slice_mut_checked(&mut self, r: Range<usize>) -> Result<&mut [u8], DtlsError> {
        self.buf.get_mut(r).ok_or(DtlsError::OutOfMemory)
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

    pub fn prepend_len_u16(&mut self) -> usize {
        self.offset += 2;
        self.offset
    }

    pub fn submit_prepend_len_u16(&mut self, offset: usize) -> Result<(), DtlsError> {
        let length = self.offset - offset;
        if length > u16::MAX as usize {
            return Err(DtlsError::ParseError);
        }
        *self
            .buf
            .get_mut(offset - 2..offset)
            .and_then(|b| b.split_last_chunk_mut::<2>())
            .unwrap()
            .1 = (length as u16).to_be_bytes();
        Ok(())
    }

    // pub fn write_prepend_len_u16(
    //     &mut self,
    //     variable_content: &mut dyn FnMut(&mut Self) -> Result<(), DtlsError>,
    // ) -> Result<usize, DtlsError> {
    //     self.write_prepend_length(2, variable_content)
    //     self.expect_length(2)?;
    //     self.offset += 2;
    //     let offset_begin = self.offset;
    //     variable_content(self)?;
    //     let length = self.offset - offset_begin;
    //     if length > u16::MAX as usize {
    //         return Err(DtlsError::ParseError);
    //     }
    //     *self
    //         .buf
    //         .get_mut(offset_begin - 2..offset_begin)
    //         .and_then(|b| b.split_last_chunk_mut::<2>())
    //         .unwrap()
    //         .1 = (length as u16).to_be_bytes();

    //     Ok(length)
    // }

    /// Increases offset but does not write anything.
    pub fn add_offset(&mut self, len: usize) {
        debug_assert!(self.buf.len() >= len + self.offset);
        self.offset += len;
    }

    pub fn set_offset(&mut self, offset: usize) {
        debug_assert!(offset <= self.buf.len(), "{offset} < {}", self.buf.len());
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
        let l = self.buf.len().min(self.offset);
        self.buf.get_mut(..l).unwrap()
    }
}

impl AsRef<[u8]> for ParseBuffer<'_> {
    fn as_ref(&self) -> &[u8] {
        let l = self.buf.len().min(self.offset);
        self.buf.get(..l).unwrap()
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
    if expect { Ok(()) } else { Err(err) }
}

pub fn parse_expect_with(expect: bool, err: impl FnOnce() -> DtlsError) -> Result<(), DtlsError> {
    if expect { Ok(()) } else { Err(err()) }
}
