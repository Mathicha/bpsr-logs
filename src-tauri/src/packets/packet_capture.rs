use anyhow::{Result, bail};
use etherparse::{NetSlice::Ipv4, SlicedPacket, TransportSlice::Tcp};
use log::{debug, error, info, warn};
use once_cell::sync::OnceCell;
use pnet_datalink::{self, Channel::Ethernet, NetworkInterface};
use tauri::async_runtime;
use tokio::sync::{
    mpsc::{self, Receiver, Sender},
    watch,
};
use windivert::{WinDivert, prelude::WinDivertFlags};

use crate::packets::{
    opcodes::Pkt,
    packet_process,
    utils::{BinaryReader, Server, TCPReassembler},
};

// Global sender for restart signal
static RESTART_SENDER: OnceCell<watch::Sender<bool>> = OnceCell::new();

pub fn start_windivert_capture() -> Receiver<(Pkt, Vec<u8>)> {
    let (packet_sender, packet_receiver) = mpsc::channel::<(Pkt, Vec<u8>)>(1);
    let (restart_sender, mut restart_receiver) = watch::channel(false);
    RESTART_SENDER.set(restart_sender.clone()).ok();
    async_runtime::spawn(async move {
        loop {
            read_packets(&packet_sender, &mut restart_receiver).await;
            // Wait for restart signal
            while !*restart_receiver.borrow() {
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
            // Reset signal to false before next loop
            let _ = restart_sender.send(false);
        }
        // info!("oopsies {}", line!());
    });
    packet_receiver
}

#[allow(clippy::too_many_lines)]
async fn read_packets(
    packet_sender: &Sender<(Pkt, Vec<u8>)>,
    restart_receiver: &mut watch::Receiver<bool>,
) {
    let windivert = match WinDivert::network(
        "!loopback && ip && tcp", // todo: idk why but filtering by port just crashes the program, investigate?
        0,
        WinDivertFlags::new().set_sniff(),
    ) {
        Ok(windivert_handle) => {
            info!("WinDivert handle opened!");
            Some(windivert_handle)
        }
        Err(e) => {
            error!("Failed to initialize WinDivert: {}", e);
            return;
        }
    }
    .expect("Failed to initialize WinDivert"); // if windivert doesn't work just exit early - todo: maybe we want to log this with a match so its clearer?
    let mut windivert_buffer = vec![0u8; 10 * 1024 * 1024];
    let mut packet_handler = PacketHandler::default();
    while let Ok(packet) = windivert.recv(Some(&mut windivert_buffer)) {
        packet_handler
            .handle_packet(packet_sender, &packet.data, HandleFrom::Ip)
            .await;
        if *restart_receiver.borrow() {
            break;
        }
    } // todo: if it errors, it breaks out of the loop but will it ever error?
    // info!("{}", line!());
}

// Function to send restart signal from another thread/task
pub fn request_restart() {
    if let Some(sender) = RESTART_SENDER.get() {
        let _ = sender.send(true);
    }
}

enum HandleFrom {
    Ip,
    Ethernet,
}

#[derive(Default)]
struct PacketHandler {
    known_server: Option<Server>,
    tcp_reassembler: TCPReassembler,
}

impl PacketHandler {
    async fn handle_packet(
        &mut self,
        packet_sender: &Sender<(Pkt, Vec<u8>)>,
        data: &[u8],
        from: HandleFrom,
    ) {
        // info!("{}", line!());
        let sliced_packet_result = match from {
            HandleFrom::Ip => SlicedPacket::from_ip(data),
            HandleFrom::Ethernet => SlicedPacket::from_ethernet(data),
        };
        let Ok(sliced_packet) = sliced_packet_result else {
            return; // if it's not ip, go next packet
        };
        // info!("{}", line!());
        let Some(Ipv4(ip_packet)) = sliced_packet.net else {
            return;
        };
        // info!("{}", line!());
        let Some(Tcp(tcp_packet)) = sliced_packet.transport else {
            return;
        };
        // info!("{}", line!());
        let curr_server = Server::new(
            ip_packet.header().source(),
            tcp_packet.to_header().source_port,
            ip_packet.header().destination(),
            tcp_packet.to_header().destination_port,
        );
        // trace!(
        //     "{} ({}) => {:?}",
        //     curr_server,
        //     tcp_packet.payload().len(),
        //     tcp_packet.payload(),
        // );

        // 1. Try to identify game server via small packets
        if self.known_server != Some(curr_server) {
            let tcp_payload = tcp_packet.payload();
            let mut tcp_payload_reader = BinaryReader::from(tcp_payload.to_vec());
            if tcp_payload_reader.remaining() >= 10 {
                match tcp_payload_reader.read_bytes(10) {
                    Ok(bytes) => {
                        if bytes[4] == 0 {
                            const FRAG_LENGTH_SIZE: usize = 4;
                            const SIGNATURE: [u8; 6] = [0x00, 0x63, 0x33, 0x53, 0x42, 0x00];
                            let mut i = 0;
                            while tcp_payload_reader.remaining() >= FRAG_LENGTH_SIZE {
                                i += 1;
                                if i > 1000 {
                                    info!(
                                        "Line: {} - Stuck at 1. Try to identify game server via small packets?",
                                        line!()
                                    );
                                }
                                let tcp_frag_payload_len = match tcp_payload_reader.read_u32() {
                                    Ok(len) => len.saturating_sub(FRAG_LENGTH_SIZE as u32) as usize,
                                    Err(e) => {
                                        debug!("Malformed TCP fragment: failed to read_u32: {e}");
                                        break;
                                    }
                                };
                                if tcp_payload_reader.remaining() >= tcp_frag_payload_len {
                                    match tcp_payload_reader.read_bytes(tcp_frag_payload_len) {
                                        Ok(tcp_frag) => {
                                            if tcp_frag.len() >= 5 + SIGNATURE.len()
                                                && tcp_frag[5..5 + SIGNATURE.len()] == SIGNATURE
                                            {
                                                info!(
                                                    "Got Scene Server Address (by change): {curr_server}"
                                                );
                                                self.known_server = Some(curr_server);
                                                self.tcp_reassembler.clear_reassembler(
                                                    tcp_packet.sequence_number() as usize
                                                        + tcp_payload_reader.len(),
                                                );
                                                if let Err(err) = packet_sender
                                                    .send((Pkt::ServerChangeInfo, Vec::new()))
                                                    .await
                                                {
                                                    debug!("Failed to send packet: {err}");
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            debug!(
                                                "Malformed TCP fragment: failed to read_bytes: {e}"
                                            );
                                            break;
                                        }
                                    }
                                } else {
                                    break;
                                }
                            }
                        }
                    }
                    Err(e) => {
                        debug!("Malformed TCP payload: failed to read_bytes(10): {e}");
                    }
                }
            }
            // 2. Payload length is 98 = Login packets?
            if tcp_payload.len() == 98 {
                const SIGNATURE_1: [u8; 10] =
                    [0x00, 0x00, 0x00, 0x62, 0x00, 0x03, 0x00, 0x00, 0x00, 0x01];
                const SIGNATURE_2: [u8; 6] = [0x00, 0x00, 0x00, 0x00, 0x0a, 0x4e];
                if tcp_payload.len() >= 20
                    && tcp_payload[0..10] == SIGNATURE_1
                    && tcp_payload[14..20] == SIGNATURE_2
                {
                    info!("Got Scene Server Address by Login Return Packet: {curr_server}");
                    self.known_server = Some(curr_server);
                    self.tcp_reassembler.clear_reassembler(
                        tcp_packet.sequence_number() as usize + tcp_payload.len(),
                    );
                    if let Err(err) = packet_sender
                        .send((Pkt::ServerChangeInfo, Vec::new()))
                        .await
                    {
                        debug!("Failed to send packet: {err}");
                    }
                }
            }
            return;
        }

        if self.tcp_reassembler.next_seq.is_none() {
            self.tcp_reassembler.next_seq = Some(tcp_packet.sequence_number() as usize);
        }
        if self
            .tcp_reassembler
            .next_seq
            .unwrap()
            .saturating_sub(tcp_packet.sequence_number() as usize)
            == 0
        {
            self.tcp_reassembler.cache.insert(
                tcp_packet.sequence_number() as usize,
                Vec::from(tcp_packet.payload()),
            );
        }
        let mut i = 0;
        while self
            .tcp_reassembler
            .cache
            .contains_key(&self.tcp_reassembler.next_seq.unwrap())
        {
            i += 1;
            if i % 1000 == 0 {
                warn!(
                    "Potential infinite loop in cache processing: iteration={i}, next_seq={:?}, cache_size={}, _data_len={}",
                    self.tcp_reassembler.next_seq,
                    self.tcp_reassembler.cache.len(),
                    self.tcp_reassembler._data.len()
                );
            }
            let seq = &self.tcp_reassembler.next_seq.unwrap();
            let cached_tcp_data = self.tcp_reassembler.cache.get(seq).unwrap();
            if self.tcp_reassembler._data.is_empty() {
                self.tcp_reassembler._data = cached_tcp_data.clone();
            } else {
                self.tcp_reassembler
                    ._data
                    .extend_from_slice(cached_tcp_data);
            }
            self.tcp_reassembler.next_seq = Some(seq.wrapping_add(cached_tcp_data.len()));
            self.tcp_reassembler.cache.remove(seq);
        }
        while self.tcp_reassembler._data.len() > 4 {
            i += 1;
            if i % 1000 == 0 {
                let sample =
                    &self.tcp_reassembler._data[..self.tcp_reassembler._data.len().min(32)];
                warn!(
                    "Potential infinite loop in _data processing: iteration={i}, _data_len={}, sample={:?}",
                    self.tcp_reassembler._data.len(),
                    sample
                );
            }
            let packet_size =
                match BinaryReader::from(self.tcp_reassembler._data.clone()).read_u32() {
                    Ok(sz) => sz,
                    Err(e) => {
                        debug!("Malformed reassembled packet: failed to read_u32: {e}");
                        break;
                    }
                };
            if self.tcp_reassembler._data.len() < packet_size as usize {
                break;
            }
            if self.tcp_reassembler._data.len() >= packet_size as usize {
                let (left, right) = self.tcp_reassembler._data.split_at(packet_size as usize);
                let packet = left.to_vec();
                self.tcp_reassembler._data = right.to_vec();
                debug!(
                    "Processing packet at line {}: size={}",
                    line!(),
                    packet_size
                );
                packet_process::process_packet(BinaryReader::from(packet), packet_sender.clone())
                    .await;
            }
        }
    }
}

pub fn get_interfaces() -> Vec<NetworkInterface> {
    return pnet_datalink::interfaces();
}

pub fn start_pcap_capture(interface: Option<NetworkInterface>) -> Result<Receiver<(Pkt, Vec<u8>)>> {
    let interface = match interface {
        Some(interface) => interface,
        None => {
            // get first non-loopback interface
            let default_interface = pnet_datalink::interfaces()
                .into_iter()
                .find(|e| !e.is_loopback());
            match default_interface {
                Some(interface) => interface,
                None => bail!("No suitable default interface found"),
            }
        }
    };

    let (sender, receiver) = mpsc::channel(1);

    async_runtime::spawn(async move {
        info!("Started capture thread on {:?}", interface.name);

        let (_tx, mut rx) = match pnet_datalink::channel(&interface, Default::default()) {
            Ok(Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                warn!("Unhandled channel type");
                return;
            }
            Err(e) => {
                error!("Error creating datalink channel: {:?}", e);
                return;
            }
        };

        let mut packet_handler = PacketHandler::default();
        loop {
            let packet = match rx.next() {
                Ok(packet) => packet,
                Err(e) => {
                    warn!("Error reading packet: {:?}", e);
                    continue;
                }
            };

            packet_handler
                .handle_packet(&sender, packet, HandleFrom::Ethernet)
                .await;
        }
    });

    Ok(receiver)
}
