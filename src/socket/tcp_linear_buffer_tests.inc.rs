    // =========================================================================================//
    // Tests for the CLOSED state.
    // =========================================================================================//
    #[test]
    fn test_closed_reject() {
        let mut s = socket();
        assert_eq!(s.state, State::Closed);

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_reject_after_listen() {
        let mut s = socket();
        s.listen(LOCAL_END).unwrap();
        s.close();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_closed_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the LISTEN state.
    // =========================================================================================//

    #[test]
    fn test_listen_sack_option() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );

        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_listen_syn_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.state = State::Listen;
            s.listen_endpoint = LISTEN_END;
            assert_eq!(s.remote_win_shift, *shift_amt);
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(0),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_shift, *shift_amt);
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_listen_sanity() {
        let mut s = socket();
        s.listen(LOCAL_PORT).unwrap();
        sanity!(s, socket_listen());
    }

    #[test]
    fn test_listen_validation() {
        let mut s = socket();
        assert_eq!(s.listen(0), Err(ListenError::Unaddressable));
    }

    #[test]
    fn test_listen_twice() {
        let mut s = socket();
        assert_eq!(s.listen(80), Ok(()));
        // multiple calls to listen are okay if its the same local endpoint and the state is still in listening
        assert_eq!(s.listen(80), Ok(()));
        s.set_state(State::SynReceived); // state change, simulate incoming connection
        assert_eq!(s.listen(80), Err(ListenError::InvalidState));
    }

    #[test]
    fn test_listen_syn() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        sanity!(s, socket_syn_received());
    }

    #[test]
    fn test_listen_syn_reject_ack() {
        let mut s = socket_listen();

        let tcp_repr = TcpRepr {
            control: TcpControl::Syn,
            seq_number: REMOTE_SEQ,
            ack_number: Some(LOCAL_SEQ),
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_rst() {
        let mut s = socket_listen();
        let tcp_repr = TcpRepr {
            control: TcpControl::Rst,
            seq_number: REMOTE_SEQ,
            ack_number: None,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_listen_close() {
        let mut s = socket_listen();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the SYN-RECEIVED state.
    // =========================================================================================//

    #[test]
    fn test_syn_received_ack() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[cfg(feature = "socket-tcp-pause-synack")]
    #[test]
    fn test_syn_paused_ack() {
        let mut s = socket_syn_received();

        s.pause_synack(true);
        recv_nothing!(s);
        assert_eq!(s.state, State::SynReceived);

        s.pause_synack(false);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
    }

    #[test]
    fn test_syn_received_ack_too_low() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_ack_too_high() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2), // wrong
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 2,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynReceived);
    }

    #[test]
    fn test_syn_received_fin() {
        let mut s = socket_syn_received();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6 + 1),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);

        let mut s2 = socket_close_wait();
        s2.remote_last_ack = Some(REMOTE_SEQ + 1 + 6 + 1);
        s2.remote_last_win = 58;
        sanity!(s, s2);
    }

    #[test]
    fn test_syn_received_rst() {
        let mut s = socket_syn_received();
        s.listen_endpoint = LISTEN_END;
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Listen);
        assert_eq!(s.listen_endpoint, LISTEN_END);
        assert_eq!(s.tuple, None);
    }

    #[test]
    fn test_syn_received_no_window_scaling() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: None,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_scale: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
    }

    #[test]
    fn test_syn_received_window_scaling() {
        for scale in 0..14 {
            let mut s = socket_listen();
            send!(
                s,
                TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: REMOTE_SEQ,
                    ack_number: None,
                    window_scale: Some(scale),
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.state(), State::SynReceived);
            assert_eq!(s.tuple, Some(TUPLE));
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: Some(REMOTE_SEQ + 1),
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(0),
                    ..RECV_TEMPL
                }]
            );
            send!(
                s,
                TcpRepr {
                    seq_number: REMOTE_SEQ + 1,
                    ack_number: Some(LOCAL_SEQ + 1),
                    window_scale: None,
                    ..SEND_TEMPL
                }
            );
            assert_eq!(s.remote_win_scale, Some(scale));
        }
    }

    #[test]
    fn test_syn_received_close() {
        let mut s = socket_syn_received();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the SYN-SENT state.
    // =========================================================================================//

    #[test]
    fn test_connect_validation() {
        let mut s = socket();
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 0)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, REMOTE_END, (IpvXAddress::UNSPECIFIED, 1024)),
            Err(ConnectError::Unaddressable)
        );
        assert_eq!(
            s.socket
                .connect(&mut s.cx, (IpvXAddress::UNSPECIFIED, 0), LOCAL_END),
            Err(ConnectError::Unaddressable)
        );
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END)
            .expect("Connect failed with valid parameters");
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tuple, Some(TUPLE));
    }

    #[test]
    fn test_connect_unspecified_local() {
        let mut s = socket();
        assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
    }

    #[test]
    fn test_connect_specified_local() {
        let mut s = socket();
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, (REMOTE_ADDR, 80)),
            Ok(())
        );
    }

    #[test]
    fn test_connect_twice() {
        let mut s = socket();
        assert_eq!(s.socket.connect(&mut s.cx, REMOTE_END, 80), Ok(()));
        assert_eq!(
            s.socket.connect(&mut s.cx, REMOTE_END, 80),
            Err(ConnectError::InvalidState)
        );
    }

    #[test]
    fn test_syn_sent_sanity() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
        sanity!(s, socket_syn_sent());
    }

    #[test]
    fn test_syn_sent_syn_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 1000);
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_received_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);

        // The socket will then send a SYN|ACK packet.
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s);

        // The socket may retransmit the SYN|ACK packet.
        recv!(
            s,
            time 1001,
            Ok(TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                ..RECV_TEMPL
            })
        );

        // An ACK packet changes the SYN-RECEIVED state to ESTABLISHED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        sanity!(s, socket_established());
    }

    #[test]
    fn test_syn_sent_syn_ack_not_incremented() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_syn_received_rst() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );

        // A SYN packet changes the SYN-SENT state to SYN-RECEIVED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynReceived);

        // A RST packet changes the SYN-RECEIVED state to CLOSED.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_rst_no_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_rst_bad_ack() {
        let mut s = socket_syn_sent();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ,
                ack_number: Some(TcpSeqNumber(1234)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None, // Unexpected
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1), // Correct
                ..SEND_TEMPL
            }
        );

        // It should trigger no response and change no state
        recv!(s, []);
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_1() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_bad_ack_seq_2() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::None,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 123456), // WRONG
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 123456, // matching the ack_number of the unexpected ack
                ack_number: None,
                window_len: 0,
                ..RECV_TEMPL
            })
        );

        // It should trigger a RST, and change no state
        assert_eq!(s.state, State::SynSent);
    }

    #[test]
    fn test_syn_sent_close() {
        let mut s = socket();
        s.close();
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_syn_sent_sack_option() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: true,
                ..SEND_TEMPL
            }
        );
        assert!(s.remote_has_sack);

        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                sack_permitted: false,
                ..SEND_TEMPL
            }
        );
        assert!(!s.remote_has_sack);
    }

    #[test]
    fn test_syn_sent_win_scale_buffers() {
        for (buffer_size, shift_amt) in &[
            (64, 0),
            (128, 0),
            (1024, 0),
            (65535, 0),
            (65536, 1),
            (65537, 1),
            (131071, 1),
            (131072, 2),
            (524287, 3),
            (524288, 4),
            (655350, 4),
            (1048576, 5),
        ] {
            let mut s = socket_with_buffer_sizes(64, *buffer_size);
            s.local_seq_no = LOCAL_SEQ;
            assert_eq!(s.remote_win_shift, *shift_amt);
            s.socket.connect(&mut s.cx, REMOTE_END, LOCAL_END).unwrap();
            recv!(
                s,
                [TcpRepr {
                    control: TcpControl::Syn,
                    seq_number: LOCAL_SEQ,
                    ack_number: None,
                    max_seg_size: Some(BASE_MSS),
                    window_scale: Some(*shift_amt),
                    window_len: u16::try_from(*buffer_size).unwrap_or(u16::MAX),
                    sack_permitted: true,
                    ..RECV_TEMPL
                }]
            );
        }
    }

    #[test]
    fn test_syn_sent_syn_ack_no_window_scaling() {
        let mut s = socket_syn_sent_with_buffer_sizes(1048576, 1048576);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                // scaling does NOT apply to the window value in SYN packets
                window_len: 65535,
                window_scale: Some(5),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.remote_win_shift, 5);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: None,
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_shift, 0);
        assert_eq!(s.remote_win_scale, None);
        assert_eq!(s.remote_win_len, 42);
    }

    #[test]
    fn test_syn_sent_syn_ack_window_scaling() {
        let mut s = socket_syn_sent();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(7),
                window_len: 42,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Established);
        assert_eq!(s.remote_win_scale, Some(7));
        // scaling does NOT apply to the window value in SYN packets
        assert_eq!(s.remote_win_len, 42);
    }

    // =========================================================================================//
    // Tests for the ESTABLISHED state.
    // =========================================================================================//

    #[test]
    fn test_established_recv() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.rx_buffer.dequeue_many(6), &b"abcdef"[..]);
    }

    #[test]
    fn test_peek_slice() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        // Populate the recv buffer
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &send_buf[..],
                ..SEND_TEMPL
            }
        );

        // Peek into the recv buffer
        let mut peeked_buf = [0u8; BUF_SIZE];
        let actually_peeked = s.peek_slice(&mut peeked_buf[..]).unwrap();
        let mut recv_buf = [0u8; BUF_SIZE];
        let actually_recvd = s.recv_slice(&mut recv_buf[..]).unwrap();
        assert_eq!(
            &mut peeked_buf[..actually_peeked],
            &mut recv_buf[..actually_recvd]
        );
    }

    #[test]
    fn test_peek_slice_buffer_wrap() {
        const BUF_SIZE: usize = 10;

        let send_buf = b"0123456789";

        let mut s = socket_established_with_buffer_sizes(BUF_SIZE, BUF_SIZE);

        let _ = s.rx_buffer.enqueue_slice(&send_buf[..8]);
        let _ = s.rx_buffer.dequeue_many(6);
        let _ = s.rx_buffer.enqueue_slice(&send_buf[..5]);

        let mut peeked_buf = [0u8; BUF_SIZE];
        let actually_peeked = s.peek_slice(&mut peeked_buf[..]).unwrap();
        let mut recv_buf = [0u8; BUF_SIZE];
        let actually_recvd = s.recv_slice(&mut recv_buf[..]).unwrap();
        assert_eq!(
            &mut peeked_buf[..actually_peeked],
            &mut recv_buf[..actually_recvd]
        );
    }



    #[test]
    fn test_established_sliding_window_recv() {
        let mut s = socket_established();
        // Update our scaling parameters for a TCP with a scaled buffer.
        assert_eq!(s.rx_buffer.len(), 0);
        s.rx_buffer = BufferType::new(vec![0; 262143]);
        s.assembler = Assembler::new();
        s.remote_win_scale = Some(0);
        s.remote_last_win = 65535;
        s.remote_win_shift = 2;

        // Create a TCP segment that will mostly fill an IP frame.
        let mut segment: Vec<u8> = Vec::with_capacity(1400);
        for _ in 0..100 {
            segment.extend_from_slice(b"abcdefghijklmn")
        }
        assert_eq!(segment.len(), 1400);

        // Send the frame
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &segment,
                ..SEND_TEMPL
            }
        );

        // Ensure that the received window size is shifted right by 2.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1400),
                window_len: 65185,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send() {
        let mut s = socket_established();
        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_established_send_no_ack_send() {
        let mut s = socket_established();
        s.set_nagle_enabled(false);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_buf_gt_win() {
        let mut data = [0; 32];
        for (i, elem) in data.iter_mut().enumerate() {
            *elem = i as u8
        }

        let mut s = socket_established();
        s.remote_win_len = 16;
        s.send_slice(&data[..]).unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &data[0..16],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_send_window_shrink() {
        let mut s = socket_established();

        // 6 octets fit on the remote side's window, so we send them.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // - Peer doesn't ack them yet
        // - Sends data so we need to reply with an ACK
        // - ...AND and sends a window announcement that SHRINKS the window, so data we've
        //   previously sent is now outside the window. Yes, this is allowed by TCP.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 3,
                payload: &b"xyzxyz"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 6);

        println!(
            "local_seq_no={} remote_win_len={} remote_last_seq={}",
            s.local_seq_no, s.remote_win_len, s.remote_last_seq
        );

        // More data should not get sent since it doesn't fit in the window
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 64 - 6,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_receive_partially_outside_window() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"def");
            (3, ())
        })
        .unwrap();
    }

    #[test]
    fn test_established_receive_partially_outside_window_fin() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // Peer decides to retransmit (perhaps because the ACK was lost)
        // and also pushed data, and sent a FIN.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                control: TcpControl::Fin,
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"def");
            (3, ())
        })
        .unwrap();

        // We should accept the FIN, because even though the last packet was partially
        // outside the receive window, there is no hole after adding its data to the assembler.
        assert_eq!(s.state, State::CloseWait);
    }

    #[test]
    fn test_established_send_wrap() {
        let mut s = socket_established();
        let local_seq_start = TcpSeqNumber(i32::MAX - 1);
        s.local_seq_no = local_seq_start + 1;
        s.remote_last_seq = local_seq_start + 1;
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: local_seq_start + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_established_bad_ack() {
        let mut s = socket_established();
        // Already acknowledged data.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(TcpSeqNumber(LOCAL_SEQ.0 - 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        // Data not yet transmitted.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 10),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
    }

    #[test]
    fn test_established_bad_seq() {
        let mut s = socket_established();
        // Data outside of receive window.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);

        // Challenge ACKs are rate-limited, we don't get a second one immediately.
        send!(
            s,
            time 100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        // If we wait a bit, we do get a new one.
        send!(
            s,
            time 2000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 256,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_established_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::CloseWait);
        sanity!(s, socket_close_wait());
    }


    #[test]
    fn test_established_send_fin() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_rst_no_ack() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        sanity!(s, socket_fin_wait_1());
    }

    #[test]
    fn test_established_abort() {
        let mut s = socket_established();
        s.abort();
        assert_eq!(s.state, State::Closed);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Rst,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_established_rst_bad_seq() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );

        assert_eq!(s.state, State::Established);

        // Send something to advance seq by 1
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1, // correct seq
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // Send wrong rst again, check that the challenge ack is correctly updated
        // The ack number must be updated even if we don't call dispatch on the socket
        // See https://github.com/smoltcp-rs/smoltcp/issues/338
        send!(
            s,
            time 2000,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ, // Wrong seq
                ack_number: None,
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2), // this has changed
                window_len: 63,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-1 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_1_fin_ack() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        sanity!(s, socket_fin_wait_2());
    }

    #[test]
    fn test_fin_wait_1_fin_fin() {
        let mut s = socket_fin_wait_1();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        sanity!(s, socket_closing());
    }

    #[test]
    fn test_fin_wait_1_fin_with_data_queued() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef123456").unwrap();
        s.close();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            })
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
    }

    #[test]
    fn test_fin_wait_1_recv() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait1);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
    }

    #[test]
    fn test_fin_wait_1_close() {
        let mut s = socket_fin_wait_1();
        s.close();
        assert_eq!(s.state, State::FinWait1);
    }

    // =========================================================================================//
    // Tests for the FIN-WAIT-2 state.
    // =========================================================================================//

    #[test]
    fn test_fin_wait_2_fin() {
        let mut s = socket_fin_wait_2();
        send!(s, time 1_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(false));
    }

    #[test]
    fn test_fin_wait_2_recv() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_fin_wait_2_close() {
        let mut s = socket_fin_wait_2();
        s.close();
        assert_eq!(s.state, State::FinWait2);
    }

    // =========================================================================================//
    // Tests for the CLOSING state.
    // =========================================================================================//

    #[test]
    fn test_closing_ack_fin() {
        let mut s = socket_closing();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 1_000, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        });
        assert_eq!(s.state, State::TimeWait);
        sanity!(s, socket_time_wait(true));
    }

    #[test]
    fn test_closing_close() {
        let mut s = socket_closing();
        s.close();
        assert_eq!(s.state, State::Closing);
    }

    // =========================================================================================//
    // Tests for the TIME-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_time_wait_from_fin_wait_2_ack() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_time_wait_from_closing_no_ack() {
        let mut s = socket_time_wait(true);
        recv!(s, []);
    }

    #[test]
    fn test_time_wait_close() {
        let mut s = socket_time_wait(false);
        s.close();
        assert_eq!(s.state, State::TimeWait);
    }

    #[test]
    fn test_time_wait_retransmit() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(s, time 5_000, TcpRepr {
            control: TcpControl::Fin,
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 1),
            ..SEND_TEMPL
        }, Some(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.timer,
            Timer::Close {
                expires_at: Instant::from_secs(5) + CLOSE_DELAY
            }
        );
    }

    #[test]
    fn test_time_wait_timeout() {
        let mut s = socket_time_wait(false);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
        recv_nothing!(s, time 60_000);
        assert_eq!(s.state, State::Closed);
    }

    // =========================================================================================//
    // Tests for the CLOSE-WAIT state.
    // =========================================================================================//

    #[test]
    fn test_close_wait_ack() {
        let mut s = socket_close_wait();
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_close_wait_close() {
        let mut s = socket_close_wait();
        s.close();
        assert_eq!(s.state, State::LastAck);
        sanity!(s, socket_last_ack());
    }

    // =========================================================================================//
    // Tests for the LAST-ACK state.
    // =========================================================================================//
    #[test]
    fn test_last_ack_fin_ack() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_ack_not_of_fin() {
        let mut s = socket_last_ack();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::LastAck);

        // ACK received that doesn't ack the FIN: socket should stay in LastAck.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::LastAck);

        // ACK received of fin: socket should change to Closed.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_close() {
        let mut s = socket_last_ack();
        s.close();
        assert_eq!(s.state, State::LastAck);
    }

    // =========================================================================================//
    // Tests for transitioning through multiple states.
    // =========================================================================================//

    #[test]
    fn test_listen() {
        let mut s = socket();
        s.listen(LISTEN_END).unwrap();
        assert_eq!(s.state, State::Listen);
    }

    #[test]
    fn test_three_way_handshake() {
        let mut s = socket_listen();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_remote_close() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        s.close();
        assert_eq!(s.state, State::LastAck);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_local_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                // due to reordering, this is logically located...
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        // ... at this point
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_combined_fin_ack() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_simultaneous_close_raced() {
        let mut s = socket_established();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_simultaneous_close_raced_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);

        // Socket receives FIN before it has a chance to send its own data+FIN
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);

        // data + FIN + ack-of-FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::Closing);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        recv!(s, []);
    }

    #[test]
    fn test_fin_with_data() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_mutual_close_with_data_1() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
    }

    #[test]
    fn test_mutual_close_with_data_2() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        s.close();
        assert_eq!(s.state, State::FinWait1);
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::FinWait2);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 1),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 1),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.state, State::TimeWait);
    }

    // =========================================================================================//
    // Tests for retransmission on packet loss.
    // =========================================================================================//

    #[test]
    fn test_duplicate_seq_ack() {
        let mut s = socket_recved();
        // remote retransmission
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_data_retransmit() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 1050);
        recv!(s, time 2000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_bursts() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        recv!(s, time 1000, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_retransmit_timer_restart_on_partial_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 600, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The ACK of the first packet should restart the retransmit timer and delay a retransmission.
        recv_nothing!(s, time 2399);
        // The second packet should be re-sent.
        recv!(s, time 2400, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_data_retransmit_bursts_half_ack_close() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef012345").unwrap();
        s.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);
        // Acknowledge the first packet
        send!(s, time 5, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        // The second packet should be re-sent.
        recv!(s, time 1500, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"012345"[..],
            ..RECV_TEMPL
        }), exact);

        recv_nothing!(s, time 1550);
    }

    #[test]
    fn test_send_data_after_syn_ack_retransmit() {
        let mut s = socket_syn_received();
        recv!(s, time 50, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        recv!(s, time 1050, Ok(TcpRepr { // retransmit
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            max_seg_size: Some(BASE_MSS),
            ..RECV_TEMPL
        }));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        )
    }

    #[test]
    fn test_established_retransmit_for_dup_ack() {
        let mut s = socket_established();
        // Duplicate ACKs do not replace the retransmission timer
        s.send_slice(b"abc").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
        // Retransmit timer is on because all data was sent
        assert_eq!(s.tx_buffer.len(), 3);
        // ACK nothing new
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Retransmit
        recv!(s, time 4000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_established_queue_during_retransmission() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // this one is dropped
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        })); // this one is received
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // also dropped
        recv!(s, time 3000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        })); // retransmission
        send!(s, time 3005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            ..SEND_TEMPL
        }); // acknowledgement of both segments
        recv!(s, time 3010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        })); // retransmission of only unacknowledged data
    }

    #[test]
    fn test_close_wait_retransmit_reset_after_ack() {
        let mut s = socket_close_wait();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1 + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fin_wait_1_retransmit_reset_after_ack() {
        let mut s = socket_established();
        s.remote_win_len = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        s.send_slice(b"ABCDEF").unwrap();
        s.close();
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1005, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }));
        send!(s, time 1015, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
            window_len: 6,
            ..SEND_TEMPL
        });
        recv!(s, time 1020, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"ABCDEF"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_fast_retransmit_after_triple_duplicate_ack() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Send a long string of text divided into several packets
        // because of previously received "window_len"
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();
        // This packet is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Third duplicate ACK
        // Should trigger a fast retransmit of dropped packet
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // Fast retransmit packet
        recv!(s, time 1100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));

        recv!(s, time 1105, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1110, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1115, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // After all was send out, enter *normal* retransmission,
        // don't stay in fast retransmission.
        assert!(match s.timer {
            Timer::Retransmit { expires_at, .. } => expires_at > Instant::from_millis(1115),
            _ => false,
        });

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_data() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has content, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"xxxxxx"[..],
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 3,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving data"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection_with_window_update() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // Normal ACK of previously received segment
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // First duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // Second duplicate
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );

        assert_eq!(s.local_rx_dup_acks, 2, "duplicate ACK counter is not set");

        // This packet has a window update, hence should not be detected
        // as a duplicate ACK and should reset the duplicate ACK count
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 400,
                ..SEND_TEMPL
            }
        );

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving a window update"
        );
    }

    #[test]
    fn test_fast_retransmit_duplicate_detection() {
        let mut s = socket_established();
        s.remote_mss = 6;

        // Normal ACK of previously received segment
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // First duplicate, should not be counted as there is nothing to resend
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is set but wound not transmit data"
        );

        // Send a long string of text divided into several packets
        // because of small remote_mss
        s.send_slice(b"xxxxxxyyyyyywwwwwwzzzzzz").unwrap();

        // This packet is reordered in network
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"xxxxxx"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1005, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"yyyyyy"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1010, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 2),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"wwwwww"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1015, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + (6 * 3),
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"zzzzzz"[..],
            ..RECV_TEMPL
        }));

        // First duplicate ACK
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Second duplicate ACK
        send!(s, time 1055, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        // Reordered packet arrives which should reset duplicate ACK count
        send!(s, time 1060, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 3)),
            ..SEND_TEMPL
        });

        assert_eq!(
            s.local_rx_dup_acks, 0,
            "duplicate ACK counter is not reset when receiving ACK which updates send window"
        );

        // ACK all received segments
        send!(s, time 1120, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1 + (6 * 4)),
            ..SEND_TEMPL
        });
    }

    #[test]
    fn test_fast_retransmit_dup_acks_counter() {
        let mut s = socket_established();

        s.send_slice(b"abc").unwrap(); // This is lost
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        // A lot of retransmits happen here
        s.local_rx_dup_acks = u8::MAX - 1;

        // Send 3 more ACKs, which could overflow local_rx_dup_acks,
        // but intended behaviour is that we saturate the bounds
        // of local_rx_dup_acks
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 0, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.local_rx_dup_acks,
            u8::MAX,
            "duplicate ACK count should not overflow but saturate"
        );
    }

    #[test]
    fn test_fast_retransmit_zero_window() {
        let mut s = socket_established();

        send!(s, time 1000, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });

        s.send_slice(b"abc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abc"[..],
            ..RECV_TEMPL
        }));

        // 3 dup acks
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        send!(s, time 1050, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            window_len: 0, // boom
            ..SEND_TEMPL
        });

        // even though we're in "fast retransmit", we shouldn't
        // force-send anything because the remote's window is full.
        recv_nothing!(s);
    }

    #[test]
    fn test_retransmit_exponential_backoff() {
        let mut s = socket_established();
        s.send_slice(b"abcdef").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        let expected_retransmission_instant = s.rtte.retransmission_timeout().total_millis() as i64;
        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));

        // "current time" is expected_retransmission_instant, and we want to wait 2 * retransmission timeout
        let expected_retransmission_instant = 3 * expected_retransmission_instant;

        recv_nothing!(s, time expected_retransmission_instant - 1);
        recv!(s, time expected_retransmission_instant, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_data_retransmit_ack_more_than_expected() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"aaaaaabbbbbbcccccc").unwrap();

        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 12,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"cccccc"[..],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 0);

        recv_nothing!(s, time 50);

        // retransmit timer expires, we want to retransmit all 3 packets
        // but we only manage to retransmit 2 (due to e.g. lack of device buffer space)
        assert!(s.timer.is_retransmit());
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"aaaaaa"[..],
            ..RECV_TEMPL
        }));
        recv!(s, time 1000, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"bbbbbb"[..],
            ..RECV_TEMPL
        }));

        // ack first packet.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                ..SEND_TEMPL
            }
        );

        // this should keep retransmit timer on, because there's
        // still unacked data.
        assert!(s.timer.is_retransmit());

        // ack all three packets.
        // This might confuse the TCP stack because after the retransmit
        // it "thinks" the 3rd packet hasn't been transmitted yet, but it is getting acked.
        send!(
            s,
            time 3000,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 18),
                ..SEND_TEMPL
            }
        );

        // this should exit retransmit mode.
        assert!(!s.timer.is_retransmit());
        // and consider all data ACKed.
        assert!(s.tx_buffer.is_empty());
        recv_nothing!(s, time 5000);
    }

    #[test]
    fn test_retransmit_fin() {
        let mut s = socket_established();
        s.close();
        recv!(s, time 0, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));

        recv_nothing!(s, time 999);
        recv!(s, time 1000, Ok(TcpRepr {
            control: TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_retransmit_fin_wait() {
        let mut s = socket_fin_wait_1();
        // we send FIN
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            }]
        );
        // remote also sends FIN, does NOT ack ours.
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        // we ack it
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::None,
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );

        // we haven't got an ACK for our FIN, we should retransmit.
        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                control: TcpControl::Fin,
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 2),
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for window management.
    // =========================================================================================//

    #[test]
    fn test_maximum_segment_size() {
        let mut s = socket_listen();
        s.tx_buffer = BufferType::new(vec![0; 32767]);
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                max_seg_size: Some(1000),
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 32767,
                ..SEND_TEMPL
            }
        );
        s.send_slice(&[0; 1200][..]).unwrap();
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &[0; 1000][..],
                ..RECV_TEMPL
            })
        );
    }


    #[test]
    fn test_close_wait_no_window_update() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    #[test]
    fn test_time_wait_no_window_update() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                payload: &[1, 2, 3, 4],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);

        // we ack the FIN, with the reduced window size.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 6),
                window_len: 60,
                ..RECV_TEMPL
            })
        );

        let rx_buf = &mut [0; 32];
        assert_eq!(s.recv_slice(rx_buf), Ok(4));

        // check that we do NOT send a window update even if it has changed.
        recv_nothing!(s);
    }

    // =========================================================================================//
    // Tests for flow control.
    // =========================================================================================//

    #[test]
    fn test_psh_transmit() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef").unwrap();
        s.send_slice(b"123456").unwrap();
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Psh,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"123456"[..],
            ..RECV_TEMPL
        }), exact);
    }

    #[test]
    fn test_psh_receive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Psh,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 58,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_ack() {
        let mut s = socket_established();
        s.rx_buffer = BufferType::new(vec![0; 6]);
        s.assembler = Assembler::new();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"123456"[..],
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_zero_window_fin() {
        let mut s = socket_established();
        s.rx_buffer = BufferType::new(vec![0; 6]);
        s.assembler = Assembler::new();
        s.ack_delay = None;

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abcdef"[..],
                ..SEND_TEMPL
            }
        );
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 6),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );

        // Even though the sequence space for the FIN itself is outside the window,
        // it is not data, so FIN must be accepted when window full.
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + 6,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[],
                control: TcpControl::Fin,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::CloseWait);

        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 7),
                window_len: 0,
                ..RECV_TEMPL
            }]
        );
    }



    #[test]
    fn test_fill_peer_window() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        recv!(
            s,
            [
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"abcdef"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"123456"[..],
                    ..RECV_TEMPL
                },
                TcpRepr {
                    seq_number: LOCAL_SEQ + 1 + 6 + 6,
                    ack_number: Some(REMOTE_SEQ + 1),
                    payload: &b"!@#$%^"[..],
                    ..RECV_TEMPL
                }
            ]
        );
    }


    // =========================================================================================//
    // Tests for zero-window probes.
    // =========================================================================================//

    #[test]
    fn test_zero_window_probe_enter_on_win_update() {
        let mut s = socket_established();

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_enter_on_send() {
        let mut s = socket_established();

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();

        assert!(!s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        assert!(s.timer.is_zero_window_probe());

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        assert!(!s.timer.is_zero_window_probe());
    }

    #[test]
    fn test_zero_window_probe_exit_ack() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        send!(
            s,
            time 1010,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 6,
                ..SEND_TEMPL
            }
        );

        recv!(
            s,
            time 1010,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"bcdef1"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_backoff_nack_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 1100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 6999);
        recv!(
            s,
            time 7000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_backoff_no_reply() {
        let mut s = socket_established();
        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_zero_window_probe_shift() {
        let mut s = socket_established();

        s.send_slice(b"abcdef123456!@#$%^").unwrap();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        recv_nothing!(s, time 999);
        recv!(
            s,
            time 1000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        recv_nothing!(s, time 2999);
        recv!(
            s,
            time 3000,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"a"[..],
                ..RECV_TEMPL
            }]
        );

        // ack the ZWP byte, but still advertise zero window.
        // this should restart the ZWP timer.
        send!(
            s,
            time 3100,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 2),
                window_len: 0,
                ..SEND_TEMPL
            }
        );

        // ZWP should be sent at 3100+1000 = 4100
        recv_nothing!(s, time 4099);
        recv!(
            s,
            time 4100,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 2,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"b"[..],
                ..RECV_TEMPL
            }]
        );
    }

    // =========================================================================================//
    // Tests for timeouts.
    // =========================================================================================//

    #[test]
    fn test_listen_timeout() {
        let mut s = socket_listen();
        s.set_timeout(Some(Duration::from_millis(100)));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    #[test]
    fn test_connect_timeout() {
        let mut s = socket();
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 150, Ok(TcpRepr {
            control:    TcpControl::Syn,
            seq_number: LOCAL_SEQ,
            ack_number: None,
            max_seg_size: Some(BASE_MSS),
            window_scale: Some(0),
            sack_permitted: true,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::SynSent);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(250))
        );
        recv!(s, time 250, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(TcpSeqNumber(0)),
            window_scale: None,
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(2000)));
        recv_nothing!(s, time 250);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(2250))
        );
        s.send_slice(b"abcdef").unwrap();
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(1255))
        );
        recv!(s, time 1255, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }));
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(2255))
        );
        recv!(s, time 2255, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_established_keep_alive_timeout() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(50)));
        s.set_timeout(Some(Duration::from_millis(100)));
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 100);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(150))
        );
        send!(s, time 105, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(155))
        );
        recv!(s, time 155, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 155);
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(205))
        );
        recv_nothing!(s, time 200);
        recv!(s, time 205, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv_nothing!(s, time 205);
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_fin_wait_1_timeout() {
        let mut s = socket_fin_wait_1();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_last_ack_timeout() {
        let mut s = socket_last_ack();
        s.set_timeout(Some(Duration::from_millis(1000)));
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        recv!(s, time 1100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1 + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.state, State::Closed);
    }

    #[test]
    fn test_closed_timeout() {
        let mut s = socket_established();
        s.set_timeout(Some(Duration::from_millis(200)));
        s.remote_last_ts = Some(Instant::from_millis(100));
        s.abort();
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 100, Ok(TcpRepr {
            control:    TcpControl::Rst,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            ..RECV_TEMPL
        }));
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Ingress);
    }

    // =========================================================================================//
    // Tests for keep-alive.
    // =========================================================================================//

    #[test]
    fn test_responds_to_keep_alive() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            },
            Some(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_sends_keep_alive() {
        let mut s = socket_established();
        s.set_keep_alive(Some(Duration::from_millis(100)));

        // drain the forced keep-alive packet
        assert_eq!(s.socket.poll_at(&mut s.cx), PollAt::Now);
        recv!(s, time 0, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(100))
        );
        recv_nothing!(s, time 95);
        recv!(s, time 100, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(200))
        );
        recv_nothing!(s, time 195);
        recv!(s, time 200, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &[0],
            ..RECV_TEMPL
        }));

        send!(s, time 250, TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            ..SEND_TEMPL
        });
        assert_eq!(
            s.socket.poll_at(&mut s.cx),
            PollAt::Time(Instant::from_millis(350))
        );
        recv_nothing!(s, time 345);
        recv!(s, time 350, Ok(TcpRepr {
            seq_number: LOCAL_SEQ,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"\x00"[..],
            ..RECV_TEMPL
        }));
    }

    // =========================================================================================//
    // Tests for time-to-live configuration.
    // =========================================================================================//

    #[test]
    fn test_set_hop_limit() {
        let mut s = socket_syn_received();

        s.set_hop_limit(Some(0x2a));
        assert_eq!(
            s.socket.dispatch(&mut s.cx, |_, (ip_repr, _)| {
                assert_eq!(ip_repr.hop_limit(), 0x2a);
                Ok::<_, ()>(())
            }),
            Ok(())
        );

        // assert that user-configurable settings are kept,
        // see https://github.com/smoltcp-rs/smoltcp/issues/601.
        s.reset();
        assert_eq!(s.hop_limit(), Some(0x2a));
    }

    #[test]
    #[should_panic(expected = "the time-to-live value of a packet must not be zero")]
    fn test_set_hop_limit_zero() {
        let mut s = socket_syn_received();
        s.set_hop_limit(Some(0));
    }

    // =========================================================================================//
    // Tests for reassembly.
    // =========================================================================================//




    // =========================================================================================//
    // Tests for graceful vs ungraceful rx close
    // =========================================================================================//

    #[test]
    fn test_rx_close_fin() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_1() {
        let mut s = socket_fin_wait_1();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::Closing);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }

    #[test]
    fn test_rx_close_fin_in_fin_wait_2() {
        let mut s = socket_fin_wait_2();
        send!(
            s,
            TcpRepr {
                control: TcpControl::Fin,
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state, State::TimeWait);
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::Finished));
    }


    #[test]
    fn test_rx_close_rst() {
        let mut s = socket_established();
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Rst,
                seq_number: REMOTE_SEQ + 1 + 3,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();
        assert_eq!(s.recv(|_| (0, ())), Err(RecvError::InvalidState));
    }


    // =========================================================================================//
    // Tests for delayed ACK
    // =========================================================================================//

    #[test]
    fn test_delayed_ack() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            window_len: 61,
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_win() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        // Reading the data off the buffer should cause a window update.
        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        // However, no ACK or window update is immediately sent.
        recv_nothing!(s);

        // After 10ms, it is sent.
        recv!(s, time 11, Ok(TcpRepr {
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1 + 3),
            ..RECV_TEMPL
        }));
    }

    #[test]
    fn test_delayed_ack_reply() {
        let mut s = socket_established();
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"abc"[..],
                ..SEND_TEMPL
            }
        );

        s.recv(|data| {
            assert_eq!(data, b"abc");
            (3, ())
        })
        .unwrap();

        s.send_slice(&b"xyz"[..]).unwrap();

        // Writing data to the socket causes ACK to not be delayed,
        // because it is immediately sent with the data.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + 3),
                payload: &b"xyz"[..],
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS - 1],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS - 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+1 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 1)),
                window_len: (DEFAULT_MSS - 1) as u16,
                ..RECV_TEMPL
            })
        );
    }

    #[test]
    fn test_delayed_ack_every_rmss_or_more() {
        let mut s = socket_established_with_buffer_sizes(DEFAULT_MSS * 2, DEFAULT_MSS * 2);
        s.set_ack_delay(Some(ACK_DELAY_DEFAULT));
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &[0; DEFAULT_MSS],
                ..SEND_TEMPL
            }
        );

        // No ACK is immediately sent.
        recv_nothing!(s);

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + DEFAULT_MSS,
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"a"[..],
                ..SEND_TEMPL
            }
        );

        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1 + (DEFAULT_MSS + 1),
                ack_number: Some(LOCAL_SEQ + 1),
                payload: &b"b"[..],
                ..SEND_TEMPL
            }
        );

        // RMSS+2 bytes of data has been received, so ACK is sent without delay.
        recv!(
            s,
            Ok(TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1 + (DEFAULT_MSS + 2)),
                window_len: (DEFAULT_MSS - 2) as u16,
                ..RECV_TEMPL
            })
        );
    }

    // =========================================================================================//
    // Tests for Nagle's Algorithm
    // =========================================================================================//

    #[test]
    fn test_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;

        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                ..RECV_TEMPL
            }]
        );

        // If there's data in flight, full segments get sent.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                ..RECV_TEMPL
            }]
        );

        s.send_slice(b"aaabbbccc").unwrap();
        // If there's data in flight, not-full segments don't get sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"aaabbb"[..],
                ..RECV_TEMPL
            }]
        );

        // Data gets ACKd, so there's no longer data in flight
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6 + 6),
                ..SEND_TEMPL
            }
        );

        // Now non-full segment gets sent.
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6 + 6 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"ccc"[..],
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_final_packet_in_stream_doesnt_wait_for_nagle() {
        let mut s = socket_established();
        s.remote_mss = 6;
        s.send_slice(b"abcdef0").unwrap();
        s.socket.close();

        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::None,
            seq_number: LOCAL_SEQ + 1,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"abcdef"[..],
            ..RECV_TEMPL
        }), exact);
        recv!(s, time 0, Ok(TcpRepr {
            control:    TcpControl::Fin,
            seq_number: LOCAL_SEQ + 1 + 6,
            ack_number: Some(REMOTE_SEQ + 1),
            payload:    &b"0"[..],
            ..RECV_TEMPL
        }), exact);
    }

    // =========================================================================================//
    // Tests for packet filtering.
    // =========================================================================================//

    #[test]
    fn test_doesnt_accept_wrong_port() {
        let mut s = socket_established();
        s.rx_buffer = BufferType::new(vec![0; 6]);
        s.assembler = Assembler::new();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            dst_port: LOCAL_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            src_port: REMOTE_PORT + 1,
            ..SEND_TEMPL
        };
        assert!(!s.socket.accepts(&mut s.cx, &SEND_IP_TEMPL, &tcp_repr));
    }

    #[test]
    fn test_doesnt_accept_wrong_ip() {
        let mut s = socket_established();

        let tcp_repr = TcpRepr {
            seq_number: REMOTE_SEQ + 1,
            ack_number: Some(LOCAL_SEQ + 1),
            payload: &b"abcdef"[..],
            ..SEND_TEMPL
        };

        let ip_repr = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(s.socket.accepts(&mut s.cx, &ip_repr, &tcp_repr));

        let ip_repr_wrong_src = IpReprIpvX(IpvXRepr {
            src_addr: OTHER_ADDR,
            dst_addr: LOCAL_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_src, &tcp_repr));

        let ip_repr_wrong_dst = IpReprIpvX(IpvXRepr {
            src_addr: REMOTE_ADDR,
            dst_addr: OTHER_ADDR,
            next_header: IpProtocol::Tcp,
            payload_len: tcp_repr.buffer_len(),
            hop_limit: 64,
        });
        assert!(!s.socket.accepts(&mut s.cx, &ip_repr_wrong_dst, &tcp_repr));
    }

    // =========================================================================================//
    // Timer tests
    // =========================================================================================//

    #[test]
    fn test_timer_retransmit() {
        const RTO: Duration = Duration::from_millis(100);
        let mut r = Timer::new();
        assert!(!r.should_retransmit(Instant::from_secs(1)));
        r.set_for_retransmit(Instant::from_millis(1000), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1000)));
        assert!(!r.should_retransmit(Instant::from_millis(1050)));
        assert!(r.should_retransmit(Instant::from_millis(1101)));
        r.set_for_retransmit(Instant::from_millis(1101), RTO);
        assert!(!r.should_retransmit(Instant::from_millis(1101)));
        assert!(!r.should_retransmit(Instant::from_millis(1150)));
        assert!(!r.should_retransmit(Instant::from_millis(1200)));
        assert!(r.should_retransmit(Instant::from_millis(1301)));
        r.set_for_idle(Instant::from_millis(1301), None);
        assert!(!r.should_retransmit(Instant::from_millis(1350)));
    }

    #[test]
    fn test_rtt_estimator() {
        let mut r = RttEstimator::default();

        let rtos = &[
            6000, 5000, 4252, 3692, 3272, 2956, 2720, 2540, 2408, 2308, 2232, 2176, 2132, 2100,
            2076, 2060, 2048, 2036, 2028, 2024, 2020, 2016, 2012, 2012,
        ];

        for &rto in rtos {
            r.sample(2000);
            assert_eq!(r.retransmission_timeout(), Duration::from_millis(rto));
        }
    }

    #[test]
    fn test_set_get_congestion_control() {
        let mut s = socket_established();

        #[cfg(feature = "socket-tcp-reno")]
        {
            s.set_congestion_control(CongestionControl::Reno);
            assert_eq!(s.congestion_control(), CongestionControl::Reno);
        }

        #[cfg(feature = "socket-tcp-cubic")]
        {
            s.set_congestion_control(CongestionControl::Cubic);
            assert_eq!(s.congestion_control(), CongestionControl::Cubic);
        }

        s.set_congestion_control(CongestionControl::None);
        assert_eq!(s.congestion_control(), CongestionControl::None);
    }

    // =========================================================================================//
    // Timestamp tests
    // =========================================================================================//

    #[test]
    fn test_tsval_established_connection() {
        let mut s = socket_established();
        s.set_tsval_generator(Some(|| 1));

        assert!(s.timestamp_enabled());

        // First roundtrip after establishing.
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
        assert_eq!(s.tx_buffer.len(), 6);
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6),
                timestamp: Some(TcpTimestampRepr::new(500, 1)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
        // Second roundtrip.
        s.send_slice(b"foobar").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1 + 6,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"foobar"[..],
                timestamp: Some(TcpTimestampRepr::new(1, 500)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1 + 6 + 6),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.tx_buffer.len(), 0);
    }

    #[test]
    fn test_tsval_disabled_in_remote_client() {
        let mut s = socket_listen();
        s.set_tsval_generator(Some(|| 1));
        assert!(s.timestamp_enabled());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        assert!(!s.timestamp_enabled());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_tsval_disabled_in_local_server() {
        let mut s = socket_listen();
        // s.set_timestamp(false); // commented to alert if the default state changes
        assert!(!s.timestamp_enabled());
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: None,
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::SynReceived);
        assert_eq!(s.tuple, Some(TUPLE));
        assert!(!s.timestamp_enabled());
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: Some(REMOTE_SEQ + 1),
                max_seg_size: Some(BASE_MSS),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                seq_number: REMOTE_SEQ + 1,
                ack_number: Some(LOCAL_SEQ + 1),
                ..SEND_TEMPL
            }
        );
        assert_eq!(s.state(), State::Established);
        assert_eq!(s.local_seq_no, LOCAL_SEQ + 1);
        assert_eq!(s.remote_seq_no, REMOTE_SEQ + 1);
    }

    #[test]
    fn test_tsval_disabled_in_remote_server() {
        let mut s = socket();
        s.set_tsval_generator(Some(|| 1));
        assert!(s.timestamp_enabled());
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                timestamp: Some(TcpTimestampRepr::new(1, 0)),
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: None,
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamp_enabled());
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }

    #[test]
    fn test_tsval_disabled_in_local_client() {
        let mut s = socket();
        // s.set_timestamp(false); // commented to alert if the default state changes
        assert!(!s.timestamp_enabled());
        s.local_seq_no = LOCAL_SEQ;
        s.socket
            .connect(&mut s.cx, REMOTE_END, LOCAL_END.port)
            .unwrap();
        assert_eq!(s.tuple, Some(TUPLE));
        recv!(
            s,
            [TcpRepr {
                control: TcpControl::Syn,
                seq_number: LOCAL_SEQ,
                ack_number: None,
                max_seg_size: Some(BASE_MSS),
                window_scale: Some(0),
                sack_permitted: true,
                ..RECV_TEMPL
            }]
        );
        send!(
            s,
            TcpRepr {
                control: TcpControl::Syn,
                seq_number: REMOTE_SEQ,
                ack_number: Some(LOCAL_SEQ + 1),
                max_seg_size: Some(BASE_MSS - 80),
                window_scale: Some(0),
                timestamp: Some(TcpTimestampRepr::new(500, 0)),
                ..SEND_TEMPL
            }
        );
        assert!(!s.timestamp_enabled());
        s.send_slice(b"abcdef").unwrap();
        recv!(
            s,
            [TcpRepr {
                seq_number: LOCAL_SEQ + 1,
                ack_number: Some(REMOTE_SEQ + 1),
                payload: &b"abcdef"[..],
                timestamp: None,
                ..RECV_TEMPL
            }]
        );
    }
