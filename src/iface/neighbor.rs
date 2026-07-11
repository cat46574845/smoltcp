// Heads up! Before working on this file you should read, at least,
// the parts of RFC 1122 that discuss ARP.

use core::fmt;
use heapless::LinearMap;

use crate::config::IFACE_NEIGHBOR_CACHE_COUNT;
use crate::time::{Duration, Instant};
use crate::wire::{HardwareAddress, IpAddress};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GatewayNeighborConfigError {
    InvalidAddress,
}

impl fmt::Display for GatewayNeighborConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidAddress => write!(f, "gateway neighbor address is not unicast"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for GatewayNeighborConfigError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub enum GatewayNeighborUpdate {
    Ignored,
    Unchanged,
    Resolved,
    Changed,
}

#[derive(Debug, Clone, Copy)]
struct GatewayNeighbor {
    protocol_addr: IpAddress,
    hardware_addr: Option<HardwareAddress>,
    last_observed_at: Option<Instant>,
    last_probe_at: Option<Instant>,
    soft_stale_after: Duration,
}

/// A cached neighbor.
///
/// A neighbor mapping translates from a protocol address to a hardware address,
/// and contains the timestamp past which the mapping should be discarded.
#[derive(Debug, Clone, Copy)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub struct Neighbor {
    hardware_addr: HardwareAddress,
    expires_at: Instant,
}

/// An answer to a neighbor cache lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "defmt", derive(defmt::Format))]
pub(crate) enum Answer {
    /// The neighbor address is in the cache and not expired.
    Found(HardwareAddress),
    /// The neighbor address is not in the cache, or has expired.
    NotFound,
    /// The neighbor address is not in the cache, or has expired,
    /// and a lookup has been made recently.
    RateLimited,
}

impl Answer {
    /// Returns whether a valid address was found.
    pub(crate) fn found(&self) -> bool {
        match self {
            Answer::Found(_) => true,
            _ => false,
        }
    }
}

/// A neighbor cache backed by a map.
#[derive(Debug)]
pub struct Cache {
    storage: LinearMap<IpAddress, Neighbor, IFACE_NEIGHBOR_CACHE_COUNT>,
    silent_until: Instant,
    gateway: Option<GatewayNeighbor>,
}

impl Cache {
    /// Minimum delay between discovery requests, in milliseconds.
    pub(crate) const SILENT_TIME: Duration = Duration::from_millis(1_000);

    /// Neighbor entry lifetime, in milliseconds.
    pub(crate) const ENTRY_LIFETIME: Duration = Duration::from_millis(60_000);

    /// Create a cache.
    pub fn new() -> Self {
        Self {
            storage: LinearMap::new(),
            silent_until: Instant::from_millis(0),
            gateway: None,
        }
    }

    pub fn configure_gateway(
        &mut self,
        protocol_addr: IpAddress,
        timestamp: Instant,
        soft_stale_after: Duration,
    ) -> Result<(), GatewayNeighborConfigError> {
        if !protocol_addr.is_unicast() {
            return Err(GatewayNeighborConfigError::InvalidAddress);
        }

        let existing = self.storage.get(&protocol_addr).copied().and_then(|neighbor| {
            (timestamp < neighbor.expires_at).then_some(neighbor.hardware_addr)
        });
        self.gateway = Some(GatewayNeighbor {
            protocol_addr,
            hardware_addr: existing,
            last_observed_at: existing.map(|_| timestamp),
            last_probe_at: None,
            soft_stale_after,
        });
        Ok(())
    }

    pub fn configured_gateway(&self) -> Option<IpAddress> {
        self.gateway.map(|gateway| gateway.protocol_addr)
    }

    pub fn observe_gateway_hardware_addr(
        &mut self,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) -> GatewayNeighborUpdate {
        if !hardware_addr.is_unicast() {
            return GatewayNeighborUpdate::Ignored;
        }
        let Some(gateway) = self.gateway.as_mut() else {
            return GatewayNeighborUpdate::Ignored;
        };

        let update = match gateway.hardware_addr {
            None => GatewayNeighborUpdate::Resolved,
            Some(current) if current == hardware_addr => GatewayNeighborUpdate::Unchanged,
            Some(_) => GatewayNeighborUpdate::Changed,
        };
        if update != GatewayNeighborUpdate::Unchanged {
            gateway.hardware_addr = Some(hardware_addr);
        }
        gateway.last_observed_at = Some(timestamp);
        gateway.last_probe_at = None;
        let protocol_addr = gateway.protocol_addr;
        if update != GatewayNeighborUpdate::Unchanged {
            self.fill_with_expiration(
                protocol_addr,
                hardware_addr,
                timestamp + Self::ENTRY_LIFETIME,
            );
        }
        update
    }

    pub fn gateway_probe_due(&self, timestamp: Instant) -> Option<IpAddress> {
        let gateway = self.gateway?;
        let stale = match gateway.last_observed_at {
            Some(last_observed_at) => timestamp >= last_observed_at + gateway.soft_stale_after,
            None => true,
        };
        let retry_due = match gateway.last_probe_at {
            Some(last_probe_at) => timestamp >= last_probe_at + Self::SILENT_TIME,
            None => true,
        };
        (stale && retry_due).then_some(gateway.protocol_addr)
    }

    pub fn mark_gateway_probe_sent(
        &mut self,
        protocol_addr: IpAddress,
        timestamp: Instant,
    ) -> bool {
        let Some(gateway) = self.gateway.as_mut() else {
            return false;
        };
        if gateway.protocol_addr != protocol_addr {
            return false;
        }
        gateway.last_probe_at = Some(timestamp);
        true
    }

    pub fn reset_expiry_if_existing(
        &mut self,
        protocol_addr: IpAddress,
        source_hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) {
        if let Some(Neighbor {
            expires_at,
            hardware_addr,
        }) = self.storage.get_mut(&protocol_addr)
        {
            if source_hardware_addr == *hardware_addr {
                *expires_at = timestamp + Self::ENTRY_LIFETIME;
            }
        }
    }

    pub fn fill(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        timestamp: Instant,
    ) -> GatewayNeighborUpdate {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        if self
            .gateway
            .map(|gateway| gateway.protocol_addr == protocol_addr)
            .unwrap_or(false)
        {
            return self.observe_gateway_hardware_addr(hardware_addr, timestamp);
        }
        let expires_at = timestamp + Self::ENTRY_LIFETIME;
        self.fill_with_expiration(protocol_addr, hardware_addr, expires_at);
        GatewayNeighborUpdate::Ignored
    }

    pub fn fill_with_expiration(
        &mut self,
        protocol_addr: IpAddress,
        hardware_addr: HardwareAddress,
        expires_at: Instant,
    ) {
        debug_assert!(protocol_addr.is_unicast());
        debug_assert!(hardware_addr.is_unicast());

        let neighbor = Neighbor {
            expires_at,
            hardware_addr,
        };
        match self.storage.insert(protocol_addr, neighbor) {
            Ok(Some(old_neighbor)) => {
                if old_neighbor.hardware_addr != hardware_addr {
                    net_trace!(
                        "replaced {} => {} (was {})",
                        protocol_addr,
                        hardware_addr,
                        old_neighbor.hardware_addr
                    );
                }
            }
            Ok(None) => {
                net_trace!("filled {} => {} (was empty)", protocol_addr, hardware_addr);
            }
            Err((protocol_addr, neighbor)) => {
                // If we're going down this branch, it means the cache is full, and we need to evict an entry.
                let old_protocol_addr = *self
                    .storage
                    .iter()
                    .min_by_key(|(_, neighbor)| neighbor.expires_at)
                    .expect("empty neighbor cache storage")
                    .0;

                let _old_neighbor = self.storage.remove(&old_protocol_addr).unwrap();
                match self.storage.insert(protocol_addr, neighbor) {
                    Ok(None) => {
                        net_trace!(
                            "filled {} => {} (evicted {} => {})",
                            protocol_addr,
                            hardware_addr,
                            old_protocol_addr,
                            _old_neighbor.hardware_addr
                        );
                    }
                    // We've covered everything else above.
                    _ => unreachable!(),
                }
            }
        }
    }

    pub(crate) fn lookup(&self, protocol_addr: &IpAddress, timestamp: Instant) -> Answer {
        assert!(protocol_addr.is_unicast());

        if let Some(gateway) = self.gateway {
            if gateway.protocol_addr == *protocol_addr {
                if let Some(hardware_addr) = gateway.hardware_addr {
                    return Answer::Found(hardware_addr);
                }
            }
        }

        if let Some(&Neighbor {
            expires_at,
            hardware_addr,
        }) = self.storage.get(protocol_addr)
        {
            if timestamp < expires_at {
                return Answer::Found(hardware_addr);
            }
        }

        if timestamp < self.silent_until {
            Answer::RateLimited
        } else {
            Answer::NotFound
        }
    }

    pub(crate) fn limit_rate(&mut self, timestamp: Instant) {
        self.silent_until = timestamp + Self::SILENT_TIME;
    }

    pub(crate) fn flush(&mut self) {
        self.storage.clear()
    }
}

#[cfg(feature = "medium-ethernet")]
#[cfg(test)]
mod test {
    use super::*;
    #[cfg(all(feature = "proto-ipv4", not(feature = "proto-ipv6")))]
    use crate::wire::ipv4::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};
    #[cfg(feature = "proto-ipv6")]
    use crate::wire::ipv6::test::{MOCK_IP_ADDR_1, MOCK_IP_ADDR_2, MOCK_IP_ADDR_3, MOCK_IP_ADDR_4};

    use crate::wire::EthernetAddress;

    const HADDR_A: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 1]));
    const HADDR_B: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 2]));
    const HADDR_C: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 3]));
    const HADDR_D: HardwareAddress = HardwareAddress::Ethernet(EthernetAddress([0, 0, 0, 0, 0, 4]));

    #[test]
    fn test_fill() {
        let mut cache = Cache::new();

        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );
    }

    #[test]
    fn test_expire() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(
                    &MOCK_IP_ADDR_1.into(),
                    Instant::from_millis(0) + Cache::ENTRY_LIFETIME * 2
                )
                .found(),
        );
    }

    #[test]
    fn test_replace() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_B, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_B)
        );
    }

    #[test]
    fn test_evict() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(100));
        cache.fill(MOCK_IP_ADDR_2.into(), HADDR_B, Instant::from_millis(50));
        cache.fill(MOCK_IP_ADDR_3.into(), HADDR_C, Instant::from_millis(200));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_B)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000))
                .found()
        );

        cache.fill(MOCK_IP_ADDR_4.into(), HADDR_D, Instant::from_millis(300));
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(1000))
                .found()
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_4.into(), Instant::from_millis(1000)),
            Answer::Found(HADDR_D)
        );
    }

    #[test]
    fn test_hush() {
        let mut cache = Cache::new();

        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::NotFound
        );

        cache.limit_rate(Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(100)),
            Answer::RateLimited
        );
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(2000)),
            Answer::NotFound
        );
    }

    #[test]
    fn test_flush() {
        let mut cache = Cache::new();

        cache.fill(MOCK_IP_ADDR_1.into(), HADDR_A, Instant::from_millis(0));
        assert_eq!(
            cache.lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0)),
            Answer::Found(HADDR_A)
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_2.into(), Instant::from_millis(0))
                .found()
        );

        cache.flush();
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
        assert!(
            !cache
                .lookup(&MOCK_IP_ADDR_1.into(), Instant::from_millis(0))
                .found()
        );
    }

    #[test]
    fn configured_gateway_keeps_last_known_good_after_hard_expiry() {
        let mut cache = Cache::new();
        let gateway = MOCK_IP_ADDR_1.into();
        cache
            .configure_gateway(gateway, Instant::from_millis(0), Duration::from_secs(300))
            .unwrap();
        assert_eq!(cache.gateway_probe_due(Instant::from_millis(0)), Some(gateway));
        assert_eq!(
            cache.observe_gateway_hardware_addr(HADDR_A, Instant::from_millis(10)),
            GatewayNeighborUpdate::Resolved
        );

        assert_eq!(
            cache.lookup(&gateway, Instant::from_secs(3_600)),
            Answer::Found(HADDR_A)
        );
        cache.flush();
        assert_eq!(
            cache.lookup(&gateway, Instant::from_secs(3_600)),
            Answer::Found(HADDR_A)
        );
    }

    #[test]
    fn gateway_passive_observation_detects_change_and_defers_probe() {
        let mut cache = Cache::new();
        let gateway = MOCK_IP_ADDR_1.into();
        cache
            .configure_gateway(gateway, Instant::from_millis(0), Duration::from_secs(30))
            .unwrap();
        assert_eq!(
            cache.observe_gateway_hardware_addr(HADDR_A, Instant::from_secs(5)),
            GatewayNeighborUpdate::Resolved
        );
        assert_eq!(
            cache.observe_gateway_hardware_addr(HADDR_A, Instant::from_secs(10)),
            GatewayNeighborUpdate::Unchanged
        );
        assert_eq!(cache.gateway_probe_due(Instant::from_secs(39)), None);
        assert_eq!(cache.gateway_probe_due(Instant::from_secs(40)), Some(gateway));
        assert!(cache.mark_gateway_probe_sent(gateway, Instant::from_secs(40)));
        assert_eq!(cache.gateway_probe_due(Instant::from_millis(40_999)), None);
        assert_eq!(cache.gateway_probe_due(Instant::from_secs(41)), Some(gateway));

        assert_eq!(
            cache.observe_gateway_hardware_addr(HADDR_B, Instant::from_secs(42)),
            GatewayNeighborUpdate::Changed
        );
        assert_eq!(
            cache.lookup(&gateway, Instant::from_secs(42)),
            Answer::Found(HADDR_B)
        );
        assert_eq!(cache.gateway_probe_due(Instant::from_secs(70)), None);
    }

    #[test]
    fn arp_fill_resolves_configured_gateway() {
        let mut cache = Cache::new();
        let gateway = MOCK_IP_ADDR_1.into();
        cache
            .configure_gateway(gateway, Instant::from_millis(0), Duration::from_secs(30))
            .unwrap();

        assert_eq!(
            cache.fill(gateway, HADDR_A, Instant::from_millis(2)),
            GatewayNeighborUpdate::Resolved
        );
        assert_eq!(cache.lookup(&gateway, Instant::from_millis(2)), Answer::Found(HADDR_A));
    }
}
