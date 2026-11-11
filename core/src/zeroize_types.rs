//! zeroize_types.rs — Secret Wrappers with Guaranteed Zeroization on Drop

use core::ops::{Deref, DerefMut};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Fixed-size cryptographic secret buffer that automatically zeroes on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SecureKey<const N: usize> {
    inner: [u8; N],
}

impl<const N: usize> SecureKey<N> {
    pub const fn new(bytes: [u8; N]) -> Self {
        Self { inner: bytes }
    }

    pub fn from_slice(slice: &[u8]) -> Option<Self> {
        if slice.len() != N {
            return None;
        }
        let mut inner = [0u8; N];
        inner.copy_from_slice(slice);
        Some(Self { inner })
    }

    pub fn as_bytes(&self) -> &[u8; N] {
        &self.inner
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    /// Constant-time equality comparison
    pub fn ct_eq(&self, other: &Self) -> bool {
        let mut diff = 0u8;
        for i in 0..N {
            diff |= self.inner[i] ^ other.inner[i];
        }
        diff == 0
    }
}

impl<const N: usize> Drop for SecureKey<N> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl<const N: usize> ZeroizeOnDrop for SecureKey<N> {}

impl<const N: usize> Deref for SecureKey<N> {
    type Target = [u8; N];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl<const N: usize> DerefMut for SecureKey<N> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl<const N: usize> core::fmt::Debug for SecureKey<N> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecureKey<{} bytes> [REDACTED]", N)
    }
}

/// Dynamically sized sensitive byte buffer that automatically zeroes on drop.
#[derive(Clone, PartialEq, Eq)]
pub struct SecureBytes {
    inner: Vec<u8>,
}

impl SecureBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { inner: bytes }
    }

    pub fn from_slice(slice: &[u8]) -> Self {
        Self {
            inner: slice.to_vec(),
        }
    }

    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            inner: Vec::with_capacity(capacity),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.inner
    }

    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.inner
    }

    pub fn len(&self) -> usize {
        self.inner.len()
    }

    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    pub fn ct_eq(&self, other: &[u8]) -> bool {
        if self.inner.len() != other.len() {
            return false;
        }
        let mut diff = 0u8;
        for i in 0..self.inner.len() {
            diff |= self.inner[i] ^ other[i];
        }
        diff == 0
    }
}

impl Drop for SecureBytes {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl ZeroizeOnDrop for SecureBytes {}

impl Deref for SecureBytes {
    type Target = [u8];
    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for SecureBytes {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl core::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "SecureBytes<{} bytes> [REDACTED]", self.inner.len())
    }
}
