use core::fmt;
use core::hash::{Hash, Hasher};

use alloc::vec;
use alloc::vec::Vec;

use super::socket_set::SocketHandle;
use crate::wire::{IpAddress, IpEndpoint, IpRepr, TcpRepr};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct TcpFlowKey {
    local_addr: IpAddress,
    local_port: u16,
    remote_addr: IpAddress,
    remote_port: u16,
}

impl TcpFlowKey {
    pub(crate) fn new(local: IpEndpoint, remote: IpEndpoint) -> Self {
        Self {
            local_addr: local.addr,
            local_port: local.port,
            remote_addr: remote.addr,
            remote_port: remote.port,
        }
    }

    pub(crate) fn from_incoming(ip_repr: &IpRepr, tcp_repr: &TcpRepr<'_>) -> Self {
        Self {
            local_addr: ip_repr.dst_addr(),
            local_port: tcp_repr.dst_port,
            remote_addr: ip_repr.src_addr(),
            remote_port: tcp_repr.src_port,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum TcpFlowCacheError {
    Full,
    HandleOutOfRange,
}

impl fmt::Display for TcpFlowCacheError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "TCP flow cache is full"),
            Self::HandleOutOfRange => write!(f, "socket handle exceeds TCP flow cache capacity"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TcpFlowCacheError {}

#[derive(Debug, Clone, Copy)]
struct Entry {
    key: TcpFlowKey,
    handle: SocketHandle,
}

#[derive(Debug)]
pub(crate) struct TcpFlowCache {
    slots: Vec<Option<Entry>>,
    by_handle: Vec<Option<TcpFlowKey>>,
    len: usize,
}

impl TcpFlowCache {
    pub(crate) fn new(max_flows: usize) -> Self {
        let max_flows = max_flows.max(1);
        let slot_count = max_flows
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .unwrap_or_else(|| max_flows.next_power_of_two());
        Self {
            slots: vec![None; slot_count],
            by_handle: vec![None; max_flows],
            len: 0,
        }
    }

    #[inline]
    pub(crate) fn get(&self, key: &TcpFlowKey) -> Option<SocketHandle> {
        self.find_slot(key).map(|index| {
            self.slots[index]
                .as_ref()
                .expect("flow-cache lookup index must contain an entry")
                .handle
        })
    }

    pub(crate) fn insert(
        &mut self,
        key: TcpFlowKey,
        handle: SocketHandle,
    ) -> Result<(), TcpFlowCacheError> {
        let handle_index = handle.index();
        if handle_index >= self.by_handle.len() {
            return Err(TcpFlowCacheError::HandleOutOfRange);
        }

        let previous_key = self.by_handle[handle_index];
        let key_owner = self.get(&key);
        let removed_previous = usize::from(previous_key.is_some() && previous_key != Some(key));
        let removed_owner = usize::from(
            key_owner.is_some()
                && key_owner != Some(handle)
                && previous_key != Some(key),
        );
        let resulting_len = self
            .len
            .saturating_sub(removed_previous)
            .saturating_sub(removed_owner)
            + usize::from(previous_key != Some(key) || key_owner != Some(handle));
        if resulting_len > self.by_handle.len() {
            return Err(TcpFlowCacheError::Full);
        }

        if let Some(previous_key) = previous_key {
            if previous_key != key {
                self.remove_key(&previous_key);
            }
        }
        if let Some(owner) = self.get(&key) {
            if owner != handle {
                self.remove_handle(owner);
            } else {
                return Ok(());
            }
        }

        let mut index = self.home(&key);
        loop {
            if self.slots[index].is_none() {
                self.slots[index] = Some(Entry { key, handle });
                self.by_handle[handle_index] = Some(key);
                self.len += 1;
                return Ok(());
            }
            index = self.next(index);
        }
    }

    pub(crate) fn remove_handle(&mut self, handle: SocketHandle) -> bool {
        let Some(key) = self.by_handle.get(handle.index()).copied().flatten() else {
            return false;
        };
        self.remove_key(&key)
    }

    pub(crate) fn remove_key(&mut self, key: &TcpFlowKey) -> bool {
        let Some(mut hole) = self.find_slot(key) else {
            return false;
        };
        let removed = self.slots[hole]
            .take()
            .expect("flow-cache removal index must contain an entry");
        if self.by_handle[removed.handle.index()] == Some(removed.key) {
            self.by_handle[removed.handle.index()] = None;
        }
        self.len -= 1;

        let mut scan = self.next(hole);
        while let Some(entry) = self.slots[scan] {
            let home = self.home(&entry.key);
            if self.probe_distance(home, scan) > self.probe_distance(home, hole) {
                self.slots[hole] = Some(entry);
                self.slots[scan] = None;
                hole = scan;
            }
            scan = self.next(scan);
        }
        true
    }

    #[inline]
    fn find_slot(&self, key: &TcpFlowKey) -> Option<usize> {
        let mut index = self.home(key);
        loop {
            match self.slots[index] {
                Some(entry) if entry.key == *key => return Some(index),
                Some(_) => index = self.next(index),
                None => return None,
            }
        }
    }

    #[inline]
    fn home(&self, key: &TcpFlowKey) -> usize {
        let mut hasher = FlowHasher::default();
        key.hash(&mut hasher);
        hasher.finish() as usize & (self.slots.len() - 1)
    }

    #[inline]
    fn next(&self, index: usize) -> usize {
        (index + 1) & (self.slots.len() - 1)
    }

    #[inline]
    fn probe_distance(&self, home: usize, index: usize) -> usize {
        index.wrapping_sub(home) & (self.slots.len() - 1)
    }
}

#[derive(Default)]
struct FlowHasher(u64);

impl Hasher for FlowHasher {
    #[inline]
    fn finish(&self) -> u64 {
        self.0
    }

    #[inline]
    fn write(&mut self, bytes: &[u8]) {
        let mut hash = self.0 ^ 0x9e37_79b9_7f4a_7c15;
        for byte in bytes {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x100_0000_01b3);
        }
        self.0 = hash;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Ipv4Address;
    #[cfg(feature = "proto-ipv6")]
    use crate::wire::Ipv6Address;

    fn key(index: u16) -> TcpFlowKey {
        TcpFlowKey::new(
            IpEndpoint::new(Ipv4Address::new(10, 0, 0, 1).into(), 20_000 + index),
            IpEndpoint::new(Ipv4Address::new(10, 0, 0, 2).into(), 443),
        )
    }

    #[test]
    fn register_lookup_and_remove_by_handle() {
        let mut cache = TcpFlowCache::new(4);
        let handle = SocketHandle::from_index(2);
        cache.insert(key(1), handle).unwrap();

        assert_eq!(cache.get(&key(1)), Some(handle));
        assert!(cache.remove_handle(handle));
        assert_eq!(cache.get(&key(1)), None);
        assert!(!cache.remove_handle(handle));
    }

    #[test]
    fn replacing_handle_and_key_clears_both_reverse_mappings() {
        let mut cache = TcpFlowCache::new(4);
        let first = SocketHandle::from_index(0);
        let second = SocketHandle::from_index(1);
        cache.insert(key(1), first).unwrap();
        cache.insert(key(2), first).unwrap();
        assert_eq!(cache.get(&key(1)), None);
        assert_eq!(cache.get(&key(2)), Some(first));

        cache.insert(key(2), second).unwrap();
        assert_eq!(cache.get(&key(2)), Some(second));
        assert!(!cache.remove_handle(first));
        assert!(cache.remove_handle(second));
    }

    #[test]
    fn fixed_capacity_rejects_out_of_range_handle() {
        let mut cache = TcpFlowCache::new(2);
        assert_eq!(
            cache.insert(key(1), SocketHandle::from_index(2)),
            Err(TcpFlowCacheError::HandleOutOfRange)
        );
    }

    #[test]
    #[cfg(feature = "proto-ipv6")]
    fn full_tuple_distinguishes_ipv6_and_ports() {
        let mut cache = TcpFlowCache::new(4);
        let v4 = key(1);
        let v6 = TcpFlowKey::new(
            IpEndpoint::new(Ipv6Address::new(0, 0, 0, 0, 0, 0, 0, 1).into(), 20_001),
            IpEndpoint::new(Ipv6Address::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1).into(), 443),
        );
        cache.insert(v4, SocketHandle::from_index(0)).unwrap();
        cache.insert(v6, SocketHandle::from_index(1)).unwrap();

        assert_eq!(cache.get(&v4), Some(SocketHandle::from_index(0)));
        assert_eq!(cache.get(&v6), Some(SocketHandle::from_index(1)));
    }

    #[test]
    fn deletion_backshifts_probe_cluster_without_stale_entries() {
        let mut cache = TcpFlowCache::new(8);
        let mut colliding = Vec::new();
        let target_home = cache.home(&key(0));
        for index in 0..u16::MAX {
            let candidate = key(index);
            if cache.home(&candidate) == target_home {
                colliding.push(candidate);
                if colliding.len() == 4 {
                    break;
                }
            }
        }
        assert_eq!(colliding.len(), 4);
        for (index, candidate) in colliding.iter().copied().enumerate() {
            cache
                .insert(candidate, SocketHandle::from_index(index))
                .unwrap();
        }

        assert!(cache.remove_handle(SocketHandle::from_index(1)));
        assert_eq!(cache.get(&colliding[0]), Some(SocketHandle::from_index(0)));
        assert_eq!(cache.get(&colliding[1]), None);
        assert_eq!(cache.get(&colliding[2]), Some(SocketHandle::from_index(2)));
        assert_eq!(cache.get(&colliding[3]), Some(SocketHandle::from_index(3)));
    }
}
