use super::*;

impl InterfaceInner {
    #[allow(dead_code)]
    pub(crate) fn process_tcp<'frame, 's, B: SocketBufferT<'s>>(
        &mut self,
        sockets: &mut SocketSet<'s, B>,
        handled_by_raw_socket: bool,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        self.process_tcp_touched(
            sockets,
            handled_by_raw_socket,
            ip_repr,
            ip_payload,
            &mut |_| {},
        )
    }

    pub(crate) fn process_tcp_touched<'frame, 's, B: SocketBufferT<'s>>(
        &mut self,
        sockets: &mut SocketSet<'s, B>,
        handled_by_raw_socket: bool,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
        on_touched: &mut impl FnMut(SocketHandle),
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = check!(TcpPacket::new_checked(ip_payload));
        let tcp_repr = check!(TcpRepr::parse(
            &tcp_packet,
            &src_addr,
            &dst_addr,
            &self.caps.checksum
        ));

        #[cfg(feature = "alloc")]
        {
            let key = TcpFlowKey::from_incoming(&ip_repr, &tcp_repr);
            if let Some(handle) = self.tcp_flow_cache.get(&key) {
                let cached = sockets.item_mut_at(handle.index()).and_then(|item| {
                    if let crate::socket::Socket::Tcp(ref mut tcp_socket) = item.socket {
                        if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                            #[cfg(any(feature = "latency-probe", feature = "market-trace"))]
                            self.record_tcp_probe_cache_hit();
                            on_touched(item.meta.handle);
                            let packet = tcp_socket
                                .process(self, &ip_repr, &tcp_repr)
                                .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
                            if !tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                                self.tcp_flow_cache.remove_key(&key);
                            }
                            Some(packet)
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                });

                if let Some(packet) = cached {
                    return packet;
                }

                #[cfg(any(feature = "latency-probe", feature = "market-trace"))]
                self.record_tcp_probe_cache_miss();
                self.tcp_flow_cache.remove_key(&key);
            } else {
                #[cfg(any(feature = "latency-probe", feature = "market-trace"))]
                self.record_tcp_probe_cache_miss();
            }
        }

        for item in sockets.items_mut() {
            if let crate::socket::Socket::Tcp(ref mut tcp_socket) = item.socket {
                #[cfg(all(any(feature = "latency-probe", feature = "market-trace"), feature = "alloc"))]
                self.record_tcp_probe_linear_scan();
                if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                    on_touched(item.meta.handle);
                    let packet = tcp_socket
                        .process(self, &ip_repr, &tcp_repr)
                        .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
                    #[cfg(feature = "alloc")]
                    {
                        let key = TcpFlowKey::from_incoming(&ip_repr, &tcp_repr);
                        if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                            if let Err(error) = self.tcp_flow_cache.insert(key, item.meta.handle) {
                                net_debug!("TCP flow cache registration failed: {:?}", error);
                            }
                        } else {
                            self.tcp_flow_cache.remove_key(&key);
                        }
                    }
                    return packet;
                }
            }
        }

        if tcp_repr.control == TcpControl::Rst
            || ip_repr.dst_addr().is_unspecified()
            || ip_repr.src_addr().is_unspecified()
            || handled_by_raw_socket
        {
            // Never reply to a TCP RST packet with another TCP RST packet.
            // Never send a TCP RST packet with unspecified addresses.
            // Never send a TCP RST when packet has been handled by raw socket.
            None
        } else {
            // The packet wasn't handled by a socket, send a TCP RST packet.
            let (ip, tcp) = crate::socket::tcp::Socket::<crate::socket::tcp::SocketBuffer<'_>>::rst_reply(&ip_repr, &tcp_repr);
            Some(Packet::new(ip, IpPayload::Tcp(tcp)))
        }
    }
}
