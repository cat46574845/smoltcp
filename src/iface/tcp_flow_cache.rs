use core::fmt;

use alloc::vec;
use alloc::vec::Vec;

use super::socket_set::SocketHandle;
use crate::wire::{IpAddress, IpEndpoint, IpListenEndpoint, IpRepr, TcpRepr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
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

#[derive(Debug, Clone, Copy)]
struct ListenerEntry {
    endpoint: IpListenEndpoint,
    head: SocketHandle,
}

#[derive(Debug, Clone, Copy)]
struct ListenerLink {
    endpoint: IpListenEndpoint,
    previous: Option<SocketHandle>,
    next: Option<SocketHandle>,
}

/// Fixed endpoint-to-listener index. Multiple sockets may listen on the same
/// endpoint; each handle participates in one startup-sized intrusive list.
#[derive(Debug)]
pub(crate) struct TcpListenerCache {
    slots: Vec<Option<ListenerEntry>>,
    by_handle: Vec<Option<ListenerLink>>,
    len: usize,
}

impl TcpListenerCache {
    pub(crate) fn new(max_listeners: usize) -> Self {
        let max_listeners = max_listeners.max(1);
        let slot_count = max_listeners
            .checked_mul(2)
            .and_then(usize::checked_next_power_of_two)
            .unwrap_or_else(|| max_listeners.next_power_of_two());
        Self {
            slots: vec![None; slot_count],
            by_handle: vec![None; max_listeners],
            len: 0,
        }
    }

    pub(crate) fn insert(
        &mut self,
        endpoint: IpListenEndpoint,
        handle: SocketHandle,
    ) -> Result<(), TcpFlowCacheError> {
        let handle_index = handle.index();
        if handle_index >= self.by_handle.len() {
            return Err(TcpFlowCacheError::HandleOutOfRange);
        }
        self.remove_handle(handle);

        if let Some(slot) = self.find_slot(&endpoint) {
            let old_head = self.slots[slot]
                .as_ref()
                .expect("listener lookup slot must contain an entry")
                .head;
            self.by_handle[old_head.index()]
                .as_mut()
                .expect("listener endpoint head must have a reverse link")
                .previous = Some(handle);
            self.by_handle[handle_index] = Some(ListenerLink {
                endpoint,
                previous: None,
                next: Some(old_head),
            });
            self.slots[slot]
                .as_mut()
                .expect("listener lookup slot must remain occupied")
                .head = handle;
            return Ok(());
        }
        if self.len == self.by_handle.len() {
            return Err(TcpFlowCacheError::Full);
        }

        let mut slot = self.home(&endpoint);
        while self.slots[slot].is_some() {
            slot = self.next(slot);
        }
        self.slots[slot] = Some(ListenerEntry { endpoint, head: handle });
        self.by_handle[handle_index] = Some(ListenerLink {
            endpoint,
            previous: None,
            next: None,
        });
        self.len += 1;
        Ok(())
    }

    #[inline]
    pub(crate) fn get(&self, local_addr: IpAddress, local_port: u16) -> Option<SocketHandle> {
        let exact = IpListenEndpoint {
            addr: Some(local_addr),
            port: local_port,
        };
        self.get_endpoint(&exact).or_else(|| {
            self.get_endpoint(&IpListenEndpoint {
                addr: None,
                port: local_port,
            })
        })
    }

    pub(crate) fn remove_handle(&mut self, handle: SocketHandle) -> bool {
        let Some(link) = self.by_handle.get_mut(handle.index()).and_then(Option::take) else {
            return false;
        };
        if let Some(previous) = link.previous {
            self.by_handle[previous.index()]
                .as_mut()
                .expect("listener previous handle must retain its reverse link")
                .next = link.next;
        } else {
            let slot = self
                .find_slot(&link.endpoint)
                .expect("listener head endpoint must remain indexed");
            if let Some(next) = link.next {
                self.slots[slot]
                    .as_mut()
                    .expect("listener head slot must remain occupied")
                    .head = next;
            } else {
                self.remove_slot(slot);
            }
        }
        if let Some(next) = link.next {
            self.by_handle[next.index()]
                .as_mut()
                .expect("listener next handle must retain its reverse link")
                .previous = link.previous;
        }
        true
    }

    #[inline]
    fn get_endpoint(&self, endpoint: &IpListenEndpoint) -> Option<SocketHandle> {
        self.find_slot(endpoint).map(|slot| {
            self.slots[slot]
                .as_ref()
                .expect("listener lookup slot must contain an entry")
                .head
        })
    }

    fn remove_slot(&mut self, mut hole: usize) {
        self.slots[hole] = None;
        self.len -= 1;
        let mut scan = self.next(hole);
        while let Some(entry) = self.slots[scan] {
            let home = self.home(&entry.endpoint);
            if self.probe_distance(home, scan) > self.probe_distance(home, hole) {
                self.slots[hole] = Some(entry);
                self.slots[scan] = None;
                hole = scan;
            }
            scan = self.next(scan);
        }
    }

    #[inline]
    fn find_slot(&self, endpoint: &IpListenEndpoint) -> Option<usize> {
        let mut slot = self.home(endpoint);
        loop {
            match self.slots[slot] {
                Some(entry) if entry.endpoint == *endpoint => return Some(slot),
                Some(_) => slot = self.next(slot),
                None => return None,
            }
        }
    }

    #[inline]
    fn home(&self, endpoint: &IpListenEndpoint) -> usize {
        let mut hash = 0x6eed_0e9d_a4d9_4a4f;
        if let Some(address) = endpoint.addr {
            hash = mix_address(hash, address);
        }
        mix_hash(hash, u64::from(endpoint.port)) as usize & (self.slots.len() - 1)
    }

    #[inline]
    fn next(&self, slot: usize) -> usize {
        (slot + 1) & (self.slots.len() - 1)
    }

    #[inline]
    fn probe_distance(&self, home: usize, slot: usize) -> usize {
        slot.wrapping_sub(home) & (self.slots.len() - 1)
    }
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
        flow_hash(key) as usize & (self.slots.len() - 1)
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

#[inline(always)]
fn mix_hash(mut hash: u64, value: u64) -> u64 {
    hash ^= value.wrapping_mul(0x9e37_79b9_7f4a_7c15);
    hash.rotate_left(27).wrapping_mul(0x94d0_49bb_1331_11eb)
}

#[inline(always)]
fn mix_address(mut hash: u64, address: IpAddress) -> u64 {
    match address {
        #[cfg(feature = "proto-ipv4")]
        IpAddress::Ipv4(address) => mix_hash(hash, u64::from(u32::from_be_bytes(address.octets()))),
        #[cfg(feature = "proto-ipv6")]
        IpAddress::Ipv6(address) => {
            let octets = address.octets();
            hash = mix_hash(hash, u64::from_be_bytes([
                octets[0], octets[1], octets[2], octets[3],
                octets[4], octets[5], octets[6], octets[7],
            ]));
            hash = mix_hash(hash, u64::from_be_bytes([
                octets[8], octets[9], octets[10], octets[11],
                octets[12], octets[13], octets[14], octets[15],
            ]));
            hash
        }
    }
}

#[inline(always)]
fn flow_hash(key: &TcpFlowKey) -> u64 {
    let hash = mix_address(0x517c_c1b7_2722_0a95, key.local_addr);
    let hash = mix_hash(hash, u64::from(key.local_port));
    let hash = mix_address(hash, key.remote_addr);
    mix_hash(hash, u64::from(key.remote_port))
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

    #[test]
    fn listener_index_supports_many_sockets_on_one_endpoint() {
        let endpoint = IpListenEndpoint::from(443);
        let mut cache = TcpListenerCache::new(8);
        let first = SocketHandle::from_index(1);
        let second = SocketHandle::from_index(2);
        let third = SocketHandle::from_index(3);
        cache.insert(endpoint, first).unwrap();
        cache.insert(endpoint, second).unwrap();
        cache.insert(endpoint, third).unwrap();

        let local = Ipv4Address::new(10, 0, 0, 1).into();
        assert_eq!(cache.get(local, 443), Some(third));
        assert!(cache.remove_handle(second));
        assert_eq!(cache.get(local, 443), Some(third));
        assert!(cache.remove_handle(third));
        assert_eq!(cache.get(local, 443), Some(first));
        assert!(cache.remove_handle(first));
        assert_eq!(cache.get(local, 443), None);
    }

    #[test]
    fn exact_listener_precedes_wildcard_listener() {
        let address = Ipv4Address::new(10, 0, 0, 1);
        let mut cache = TcpListenerCache::new(4);
        let wildcard = SocketHandle::from_index(0);
        let exact = SocketHandle::from_index(1);
        cache.insert(IpListenEndpoint::from(443), wildcard).unwrap();
        cache
            .insert(IpListenEndpoint::from((address, 443)), exact)
            .unwrap();

        assert_eq!(cache.get(address.into(), 443), Some(exact));
        assert_eq!(
            cache.get(Ipv4Address::new(10, 0, 0, 2).into(), 443),
            Some(wildcard)
        );
    }
}
