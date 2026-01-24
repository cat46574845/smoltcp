use core::fmt;
use managed::ManagedSlice;

use super::socket_meta::Meta;
use crate::socket::{AnySocket, Socket};
use crate::storage::{SocketBufferT, RingBuffer};

/// Opaque struct with space for storing one socket.
///
/// This is public so you can use it to allocate space for storing
/// sockets when creating an Interface.
///
/// The type parameter `B` specifies the buffer type for TCP sockets.
#[derive(Debug)]
pub struct SocketStorage<'a, B: SocketBufferT<'a> = RingBuffer<'a, u8>> {
    inner: Option<Item<'a, B>>,
}

// Manual Default implementation that doesn't require B: Default
impl<'a, B: SocketBufferT<'a>> Default for SocketStorage<'a, B> {
    fn default() -> Self {
        Self { inner: None }
    }
}

impl<'a, B: SocketBufferT<'a>> SocketStorage<'a, B> {
    pub const EMPTY: Self = Self { inner: None };
}

/// An item of a socket set.
#[derive(Debug)]
pub(crate) struct Item<'a, B: SocketBufferT<'a> = RingBuffer<'a, u8>> {
    pub(crate) meta: Meta,
    pub(crate) socket: Socket<'a, B>,
}

/// A handle, identifying a socket in an Interface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default, Hash)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct SocketHandle(usize);

impl fmt::Display for SocketHandle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "#{}", self.0)
    }
}

/// An extensible set of sockets.
///
/// The lifetime `'a` is used when storing a `Socket<'a>`.  If you're using
/// owned buffers for your sockets (passed in as `Vec`s) you can use
/// `SocketSet<'static>`.
///
/// The type parameter `B` specifies the buffer type for TCP sockets.
/// It defaults to `RingBuffer<'a, u8>` for backwards compatibility.
#[derive(Debug)]
pub struct SocketSet<'a, B: SocketBufferT<'a> = RingBuffer<'a, u8>> {
    sockets: ManagedSlice<'a, SocketStorage<'a, B>>,
}

impl<'a, B: SocketBufferT<'a>> SocketSet<'a, B> {
    /// Create a socket set using the provided storage.
    pub fn new<SocketsT>(sockets: SocketsT) -> SocketSet<'a, B>
    where
        SocketsT: Into<ManagedSlice<'a, SocketStorage<'a, B>>>,
    {
        let sockets = sockets.into();
        SocketSet { sockets }
    }

    /// Add a socket to the set, and return its handle.
    ///
    /// # Panics
    /// This function panics if the storage is fixed-size (not a `Vec`) and is full.
    pub fn add<T: AnySocket<'a, B>>(&mut self, socket: T) -> SocketHandle {
        fn put<'a, B: SocketBufferT<'a>>(index: usize, slot: &mut SocketStorage<'a, B>, socket: Socket<'a, B>) -> SocketHandle {
            net_trace!("[{}]: adding", index);
            let handle = SocketHandle(index);
            let mut meta = Meta::default();
            meta.handle = handle;
            *slot = SocketStorage {
                inner: Some(Item { meta, socket }),
            };
            handle
        }

        let socket = socket.upcast();

        for (index, slot) in self.sockets.iter_mut().enumerate() {
            if slot.inner.is_none() {
                return put(index, slot, socket);
            }
        }

        match &mut self.sockets {
            ManagedSlice::Borrowed(_) => panic!("adding a socket to a full SocketSet"),
            #[cfg(feature = "alloc")]
            ManagedSlice::Owned(sockets) => {
                sockets.push(SocketStorage { inner: None });
                let index = sockets.len() - 1;
                put(index, &mut sockets[index], socket)
            }
        }
    }

    /// Get a socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get<T: AnySocket<'a, B>>(&self, handle: SocketHandle) -> &T {
        match self.sockets[handle.0].inner.as_ref() {
            Some(item) => {
                T::downcast(&item.socket).expect("handle refers to a socket of a wrong type")
            }
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get a mutable socket from the set by its handle, as mutable.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set
    /// or the socket has the wrong type.
    pub fn get_mut<T: AnySocket<'a, B>>(&mut self, handle: SocketHandle) -> &mut T {
        match self.sockets[handle.0].inner.as_mut() {
            Some(item) => T::downcast_mut(&mut item.socket)
                .expect("handle refers to a socket of a wrong type"),
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Remove a socket from the set, without changing its state.
    ///
    /// # Panics
    /// This function may panic if the handle does not belong to this socket set.
    pub fn remove(&mut self, handle: SocketHandle) -> Socket<'a, B> {
        net_trace!("[{}]: removing", handle.0);
        match self.sockets[handle.0].inner.take() {
            Some(item) => item.socket,
            None => panic!("handle does not refer to a valid socket"),
        }
    }

    /// Get an iterator to the inner sockets.
    pub fn iter(&self) -> impl Iterator<Item = (SocketHandle, &Socket<'a, B>)> {
        self.items().map(|i| (i.meta.handle, &i.socket))
    }

    /// Get a mutable iterator to the inner sockets.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (SocketHandle, &mut Socket<'a, B>)> {
        self.items_mut().map(|i| (i.meta.handle, &mut i.socket))
    }

    /// Iterate every socket in this set.
    pub(crate) fn items(&self) -> impl Iterator<Item = &Item<'a, B>> + '_ {
        self.sockets.iter().filter_map(|x| x.inner.as_ref())
    }

    /// Iterate every socket in this set.
    pub(crate) fn items_mut(&mut self) -> impl Iterator<Item = &mut Item<'a, B>> + '_ {
        self.sockets.iter_mut().filter_map(|x| x.inner.as_mut())
    }
}

