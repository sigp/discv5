//! This implements an identity hash used for the ECDH library.
//!
//! As we feed the `SharedSecret` obtained from `libsecp256k1::ecdh::new()` into the hkdf expand
//! function, hashing the intermediate result is unnecessary. We therefore use this identity hash
//! type to avoid intermediate hashing.
//!
//! This `Identity` hash stores a 33 byte generic array.

use digest::{
    generic_array::{typenum::U33, GenericArray},
    Digest,
};

pub(crate) struct EcdhIdent {
    /// The contents from `input()`
    inner: GenericArray<u8, U33>,
    /// The current index to insert content
    index: usize,
}

impl Digest for EcdhIdent {
    type OutputSize = U33;

    fn new() -> Self {
        EcdhIdent {
            inner: GenericArray::clone_from_slice(&vec![0; 33]),
            index: 0,
        }
    }

    fn input<B: AsRef<[u8]>>(&mut self, data: B) {
        // make sure input doesn't overflow
        if data.as_ref().len() <= 33 - self.index {
            self.inner[self.index..self.index + data.as_ref().len()].copy_from_slice(data.as_ref());
            self.index += data.as_ref().len();
        }
    }

    /// This digest should only be used for the ecdh library. If data is longer than 33 bytes it is
    /// truncated.
    fn chain<B: AsRef<[u8]>>(self, data: B) -> Self {
        let input_data = if data.as_ref().len() <= 33 {
            &data.as_ref()[..]
        } else {
            &data.as_ref()[..33]
        };
        EcdhIdent {
            inner: GenericArray::clone_from_slice(input_data),
            index: data.as_ref().len(),
        }
    }

    fn result(self) -> GenericArray<u8, Self::OutputSize> {
        self.inner
    }

    fn result_reset(&mut self) -> GenericArray<u8, Self::OutputSize> {
        let result = self.inner;
        self.inner = GenericArray::clone_from_slice(&vec![0; 33]);
        self.index = 0;
        result
    }

    fn reset(&mut self) {
        self.inner = GenericArray::clone_from_slice(&vec![0; 33]);
        self.index = 0;
    }

    fn output_size() -> usize {
        33usize
    }

    fn digest(data: &[u8]) -> GenericArray<u8, Self::OutputSize> {
        let mut h = EcdhIdent::new();
        h.input(data);
        h.result()
    }
}

impl Default for EcdhIdent {
    fn default() -> Self {
        EcdhIdent::new()
    }
}
