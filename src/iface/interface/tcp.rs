use super::*;

impl InterfaceInner {
    pub(crate) fn process_tcp<'frame, 's, B: SocketBufferT<'s>>(
        &mut self,
        sockets: &mut SocketSet<'s, B>,
        handled_by_raw_socket: bool,
        ip_repr: IpRepr,
        ip_payload: &'frame [u8],
    ) -> Option<Packet<'frame>> {
        let (src_addr, dst_addr) = (ip_repr.src_addr(), ip_repr.dst_addr());
        let tcp_packet = check!(TcpPacket::new_checked(ip_payload));
        let tcp_repr = check!(TcpRepr::parse(
            &tcp_packet,
            &src_addr,
            &dst_addr,
            &self.caps.checksum
        ));

        for item in sockets.items_mut() {
            if let crate::socket::Socket::Tcp(ref mut tcp_socket) = item.socket {
                if tcp_socket.accepts(self, &ip_repr, &tcp_repr) {
                    return tcp_socket
                        .process(self, &ip_repr, &tcp_repr)
                        .map(|(ip, tcp)| Packet::new(ip, IpPayload::Tcp(tcp)));
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
