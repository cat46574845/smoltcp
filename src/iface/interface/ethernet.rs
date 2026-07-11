use super::*;

impl InterfaceInner {
    #[allow(dead_code)]
    pub(super) fn process_ethernet<'frame, 's, B: SocketBufferT<'s>>(
        &mut self,
        sockets: &mut SocketSet<'s, B>,
        meta: crate::phy::PacketMeta,
        frame: &'frame [u8],
        fragments: &'frame mut FragmentsBuffer,
    ) -> Option<EthernetPacket<'frame>> {
        self.process_ethernet_touched(sockets, meta, frame, fragments, &mut |_| {})
    }

    #[inline(always)]
    pub(super) fn process_ethernet_touched<'frame, 's, B: SocketBufferT<'s>>(
        &mut self,
        sockets: &mut SocketSet<'s, B>,
        meta: crate::phy::PacketMeta,
        frame: &'frame [u8],
        fragments: &'frame mut FragmentsBuffer,
        on_touched: &mut impl FnMut(SocketHandle),
    ) -> Option<EthernetPacket<'frame>> {
        self.process_ethernet_touched_with_gateway_observer(
            sockets,
            meta,
            frame,
            fragments,
            &mut IgnoreGatewayIngress,
            on_touched,
        )
    }

    pub(super) fn process_ethernet_touched_with_gateway_observer<
        'frame,
        's,
        B: SocketBufferT<'s>,
        O: GatewayIngressObserver,
    >(
        &mut self,
        sockets: &mut SocketSet<'s, B>,
        meta: crate::phy::PacketMeta,
        frame: &'frame [u8],
        #[allow(unused_variables)]
        fragments: &'frame mut FragmentsBuffer,
        #[allow(unused_variables)]
        gateway_observer: &mut O,
        on_touched: &mut impl FnMut(SocketHandle),
    ) -> Option<EthernetPacket<'frame>> {
        let eth_frame = check!(EthernetFrame::new_checked(frame));

        // Ignore any packets not directed to our hardware address or any of the multicast groups.
        if !eth_frame.dst_addr().is_broadcast()
            && !eth_frame.dst_addr().is_multicast()
            && HardwareAddress::Ethernet(eth_frame.dst_addr()) != self.hardware_addr
        {
            return None;
        }

        match eth_frame.ethertype() {
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Arp => self.process_arp_touched(
                self.now,
                &eth_frame,
                &mut |neighbor| {
                    sockets.activate_neighbor_waiters(neighbor, &mut *on_touched);
                },
            ),
            #[cfg(feature = "proto-ipv4")]
            EthernetProtocol::Ipv4 => {
                let ipv4_packet = check!(Ipv4Packet::new_checked(eth_frame.payload()));

                self.process_ipv4_touched_with_gateway_observer(
                    sockets,
                    meta,
                    eth_frame.src_addr().into(),
                    &ipv4_packet,
                    fragments,
                    gateway_observer,
                    on_touched,
                )
                .map(EthernetPacket::Ip)
            }
            #[cfg(feature = "proto-ipv6")]
            EthernetProtocol::Ipv6 => {
                let ipv6_packet = check!(Ipv6Packet::new_checked(eth_frame.payload()));
                self.process_ipv6_touched(
                    sockets,
                    meta,
                    eth_frame.src_addr().into(),
                    &ipv6_packet,
                    on_touched,
                )
                    .map(EthernetPacket::Ip)
            }
            // Drop all other traffic.
            _ => None,
        }
    }

    pub(super) fn dispatch_ethernet<Tx, F>(
        &mut self,
        tx_token: Tx,
        buffer_len: usize,
        f: F,
    ) -> Result<(), DispatchError>
    where
        Tx: TxToken,
        F: FnOnce(EthernetFrame<&mut [u8]>),
    {
        let tx_len = EthernetFrame::<&[u8]>::buffer_len(buffer_len);
        tx_token.consume(tx_len, |tx_buffer| {
            debug_assert!(tx_buffer.as_ref().len() == tx_len);
            let mut frame = EthernetFrame::new_unchecked(tx_buffer);

            let src_addr = self.hardware_addr.ethernet_or_panic();
            frame.set_src_addr(src_addr);

            f(frame);

            Ok(())
        })
    }
}
