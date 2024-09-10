use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Instant,
};

use crate::{
    internal::{messages::{
        DeserializedMessage, MessageId, MessagePart, MessagePartId,
        MessagePartMapTryInsertResult, MessagePartMapTryReadResult,
    }, rt::TaskHandle, MessageChannel},
    packets::{
        SerializedPacket, SerializedPacketList,
    }
};

use super::*;

pub mod client {
    use super::*;

    pub async fn create_receiving_bytes_handler(
        server: Weak<ServerInternal>,
        addr: SocketAddr,
        client: Weak<ConnectedClient>,
        receiving_bytes_receiver: async_channel::Receiver<Vec<u8>>,
    ) {
        'l1: while let Ok(bytes) = receiving_bytes_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                if let Some(client) = client.upgrade() {
                    let mut messaging = client.messaging.lock().await;
                    match bytes[0] {
                        MessageChannel::MESSAGE_PART_CONFIRM => {
                            if bytes.len() == 3 {
                                let message_id = MessageId::from_be_bytes([bytes[1], bytes[2]]);
                                if let Some((sent_instant, _)) =
                                    messaging.pending_confirmation.remove(&message_id)
                                {
                                    let delay = Instant::now() - sent_instant;
                                    messaging.latency_monitor.push(delay);
                                    messaging.average_packet_loss_rtt = messaging.packet_loss_rtt_calculator.update_rtt(
                                        &server.messaging_properties.packet_loss_rtt_properties,
                                        delay,
                                    );
                                }
                            } else if bytes.len() == 5 {
                                let message_id = MessageId::from_be_bytes([bytes[1], bytes[2]]);
                                let part_id = MessagePartId::from_be_bytes([bytes[3], bytes[4]]);
                                if let Some((sent_instant, map)) =
                                    messaging.pending_confirmation.get_mut(&message_id)
                                {
                                    let sent_instant = *sent_instant;
                                    if let Some(_) = map.remove(&part_id) {
                                        if map.is_empty() {
                                            messaging.pending_confirmation.remove(&message_id).unwrap();
                                        }

                                        let delay = Instant::now() - sent_instant;
                                        messaging.latency_monitor.push(delay);
                                        messaging.average_packet_loss_rtt = messaging.packet_loss_rtt_calculator.update_rtt(
                                            &server.messaging_properties.packet_loss_rtt_properties,
                                            delay,
                                        );
                                    }
                                }
                            } else {
                                drop(messaging);
                                let _ = server.clients_to_disconnect_sender.try_send((
                                    addr,
                                    (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                ));
                                break 'l1;
                            }
                        }
                        MessageChannel::MESSAGE_PART_SEND => {
                            let message_part_bytes = client.inner_auth.extract_after_channel(&bytes);

                            let message_part_bytes = match message_part_bytes {
                                Ok(message_part_bytes) => message_part_bytes,
                                Err(_) => {
                                    drop(messaging);
                                    let _ = server.clients_to_disconnect_sender.try_send((
                                        addr,
                                        (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                    ));
                                    break 'l1;
                                }
                            };

                            if let Ok(part) = MessagePart::deserialize(message_part_bytes) {
                                let mut send_fully_message_confirmation = false;
                                let message_id = part.message_id();
                                let part_id = part.id();

                                match messaging.incoming_messages.try_insert(part) {
                                    MessagePartMapTryInsertResult::PastMessageId => {
                                        let _ = client
                                            .message_part_confirmation_sender
                                            .try_send((message_id, None));
                                    },
                                    MessagePartMapTryInsertResult::Stored => {
                                        'l2: loop {
                                            match messaging.incoming_messages.try_read(&server.packet_registry){
                                                MessagePartMapTryReadResult::PendingParts => break 'l2,
                                                MessagePartMapTryReadResult::ErrorInCompleteMessageDeserialize(_) => {
                                                    let _ = server.clients_to_disconnect_sender.try_send((
                                                        addr,
                                                        (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                                    ));
                                                    break 'l1;
                                                },
                                                MessagePartMapTryReadResult::SuccessfullyCreated(message) => {
                                                    send_fully_message_confirmation = true;
        
                                                    messaging.received_messages.push(message);
                                                    messaging.last_received_message_instant = Instant::now();
                                                },
                                            }
                                        }
        
                                        if send_fully_message_confirmation {
                                            let _ = client
                                                .message_part_confirmation_sender
                                                .try_send((message_id, None));
                                        } else {
                                            let _ = client
                                                .message_part_confirmation_sender
                                                .try_send((message_id, Some(part_id)));
                                        }
                                    },
                                }

                                *client.incoming_messages_total_size.write().unwrap() = messaging.incoming_messages.total_size();
                            } else {
                                let _ = server.clients_to_disconnect_sender.try_send((
                                    addr,
                                    (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                ));
                                break 'l1;
                            }
                        }
                        MessageChannel::REJECTION_JUSTIFICATION => {
                            let justification_bytes = client.inner_auth.extract_after_channel(&bytes);

                            let justification_bytes = match justification_bytes {
                                Ok(justification_bytes) => justification_bytes,
                                Err(_) => {
                                    let _ = server.clients_to_disconnect_sender.try_send((
                                        addr,
                                        (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                    ));
                                    break 'l1;
                                }
                            };

                            if let Ok(message) =
                                DeserializedMessage::deserialize_single_list(&justification_bytes, &server.packet_registry)
                            {
                                server.recently_disconnected.insert(addr, Instant::now());
                                server.rejections_to_confirm.insert(addr);

                                let _ = server
                                    .clients_to_disconnect_sender
                                    .try_send((addr, (ClientDisconnectReason::DisconnectRequest(message), None)));
                                break 'l1;
                            } else {
                                let _ = server.clients_to_disconnect_sender.try_send((
                                    addr,
                                    (ClientDisconnectReason::InvalidProtocolCommunication, None),
                                ));
                                break 'l1;
                            }
                        }
                        MessageChannel::AUTH_MESSAGE => {
                            // Client probably multiple authentication packets before being authenticated
                        }
                        _ => {
                            let _ = server.clients_to_disconnect_sender.try_send((
                                addr,
                                (ClientDisconnectReason::InvalidProtocolCommunication, None),
                            ));
                            break 'l1;
                        }
                    }
                } else {
                    break 'l1;
                }
            } else {
                break 'l1;
            }
        } 
    }

    pub async fn create_packets_to_send_handler(
        server: Weak<ServerInternal>,
        client: Weak<ConnectedClient>,
        packets_to_send_receiver: async_channel::Receiver<Option<SerializedPacket>>,
        mut next_message_id: MessagePartId,
    ) {
        let mut packets_to_send: Vec<SerializedPacket> = Vec::new();

        'l1: while let Ok(serialized_packet) = packets_to_send_receiver.recv().await {
            if let Some(serialized_packet) = serialized_packet {
                packets_to_send.push(serialized_packet);
            } else {
                if let Some(server) = server.upgrade() {
                    if let Some(client) = client.upgrade() {
                        let mut messaging = client.messaging.lock().await;
                        let packets_to_send = std::mem::replace(&mut packets_to_send, Vec::new());

                        let serialized_packet_list = SerializedPacketList::non_empty(packets_to_send);
                        push_completed_message_tick(&server, &client, &mut messaging, &client.shared_socket_bytes_send_sender, next_message_id, serialized_packet_list);

                        next_message_id = next_message_id.wrapping_add(1);
                    } else {
                        break 'l1;
                    }
                } else {
                    break 'l1;
                }
            }
        }
    }

    pub fn push_completed_message_tick(
        server: &ServerInternal, 
        client: &ConnectedClient,
        messaging: &mut ConnectedClientMessaging,
        shared_socket_bytes_send_sender: &async_channel::Sender<Arc<Vec<u8>>>,
        message_id: MessageId, 
        serialized_packet_list: SerializedPacketList) {
        let bytes = serialized_packet_list.bytes;
        
        let message_parts = MessagePart::create_list(
            &server.messaging_properties,
            message_id,
            bytes,
        )
        .unwrap();
    
        let sent_instant = Instant::now();
    
        for part in message_parts {
            let part_id = part.id();
            let part_message_id = part.message_id();

            let sent_part = client.inner_auth.sent_part_of(sent_instant, part);

            let finished_bytes = Arc::clone(&sent_part.finished_bytes);
    
            let (_, pending_part_id_map) = messaging
                .pending_confirmation
                .entry(part_message_id)
                .or_insert_with(|| (sent_instant, BTreeMap::new()));
            pending_part_id_map.insert(part_id, sent_part);
    
            let _ = shared_socket_bytes_send_sender
                .try_send(finished_bytes);
        }
    }
    
    pub async fn create_message_part_confirmation_handler(
        server: Weak<ServerInternal>,
        addr: SocketAddr,
        message_part_confirmation_receiver: async_channel::Receiver<(
            MessageId,
            Option<MessagePartId>,
        )>,
    ) {
        'l1: while let Ok((message_id, part_id)) = message_part_confirmation_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                let message_id_bytes = message_id.to_be_bytes();

                let bytes = {
                    if let Some(part_id) = part_id {
                        let part_id_bytes = part_id.to_be_bytes();
                        vec![
                            MessageChannel::MESSAGE_PART_CONFIRM,
                            message_id_bytes[0],
                            message_id_bytes[1],
                            part_id_bytes[0],
                            part_id_bytes[1],
                        ]
                    } else {
                        vec![
                            MessageChannel::MESSAGE_PART_CONFIRM,
                            message_id_bytes[0],
                            message_id_bytes[1],
                        ]
                    }
                };
                if let Err(e) = server.socket.send_to(&bytes, addr).await {
                    let _ = server.clients_to_disconnect_sender.try_send((
                        addr,
                        (ClientDisconnectReason::ByteSendError(e), None),
                    ));
                    break 'l1;
                }
            } else {
                break 'l1;
            }
        }
    }

    pub async fn create_shared_socket_bytes_send_handler(
        server: Weak<ServerInternal>,
        addr: SocketAddr,
        shared_socket_bytes_send_receiver: async_channel::Receiver<Arc<Vec<u8>>>,
    ) {
        'l1: while let Ok(bytes) = shared_socket_bytes_send_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                if let Err(e) = server.socket.send_to(&bytes, addr).await {
                    let _ = server.clients_to_disconnect_sender.try_send((
                        addr,
                        (ClientDisconnectReason::ByteSendError(e), None),
                    ));
                    break 'l1;
                }
            } else {
                break 'l1;
            }
        }
    }
}

pub mod server {
    use super::*;

    #[cfg(feature = "rt_tokio")]
    pub async fn create_async_tasks_keeper(
        tasks_keeper_receiver: async_channel::Receiver<TaskHandle<()>>,
    ) {
        while let Ok(handle) = tasks_keeper_receiver.recv().await {
            handle.await.unwrap();
        }
    }
    #[cfg(not(feature = "rt_tokio"))]
    pub async fn create_async_tasks_keeper(
        tasks_keeper_receiver: async_channel::Receiver<TaskHandle<()>>,
    ) {
        while let Ok(handle) = tasks_keeper_receiver.recv().await {
            handle.await;
        }
    }

    pub async fn create_pending_rejection_confirm_resend_handler(
        server: Weak<ServerInternal>,
        pending_rejection_confirm_resend_receiver: async_channel::Receiver<SocketAddr>,
    ) {
        'l1: while let Ok(addr) = pending_rejection_confirm_resend_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                if let Some(mut tuple) = server.pending_rejection_confirm.get_mut(&addr) {
                    let (context, last_sent_time) = tuple.value_mut();
                    *last_sent_time = Some(Instant::now());
                    let _ = server.socket.send_to(&context.finished_bytes, addr).await;
                }
            } else {
                break 'l1;
            }
        }
    }

    pub async fn create_rejections_to_confirm_handler(
        server: Weak<ServerInternal>,
        rejections_to_confirm_signal_receiver: async_channel::Receiver<()>,
    ) {
        let rejection_confirm_bytes = &vec![MessageChannel::REJECTION_CONFIRM];
        'l1: while let Ok(_) = rejections_to_confirm_signal_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                for addr in server.rejections_to_confirm.iter() {
                    let _ = server
                        .socket
                        .send_to(rejection_confirm_bytes, *addr)
                        .await;
                }
                server.rejections_to_confirm.clear();
            } else {
                break 'l1;
            }
        }
    }

    #[cfg(feature = "store_unexpected")]
    pub async fn create_store_unexpected_error_list_handler(
        server: Weak<ServerInternal>,
        create_list_signal_receiver: async_channel::Receiver<()>,
    ) {
        'l1: while let Ok(_) = create_list_signal_receiver.recv().await {
            if let Some(server) = server.upgrade() {
                let mut list = Vec::<UnexpectedError>::new();
                while let Ok(error_list) = server.store_unexpected_errors.error_list_receiver.try_recv() {
                    list.extend(error_list);
                }
                while let Ok(error) = server.store_unexpected_errors.error_receiver.try_recv() {
                    list.push(error);
                }
                
                let _ = server.store_unexpected_errors.error_list_sender.send(list).await;
            } else {
                break 'l1;
            }
        }
    }

    pub async fn create_read_handler(weak_server: Weak<ServerInternal>) {
        let mut was_used = false;
        'l1: loop {
            if let Some(server) = weak_server.upgrade() {
                if *server.read_handler_properties.active_count.write().unwrap()
                    > server.read_handler_properties.target_surplus_size + 1
                {
                    let mut surplus_count =
                        server.read_handler_properties.active_count.write().unwrap();
                    if !was_used {
                        *surplus_count -= 1;
                    }
                    break 'l1;
                } else {
                    let read_timeout = server.read_handler_properties.timeout;
                    let socket = Arc::clone(&server.socket);
                    drop(server);

                    let pre_read_next_bytes_result =
                        ServerInternal::pre_read_next_bytes(&socket, read_timeout).await;

                    if let Some(server) = weak_server.upgrade() {
                        match pre_read_next_bytes_result {
                            Ok(result) => {
                                if !was_used {
                                    was_used = true;
                                    let mut surplus_count = server
                                        .read_handler_properties
                                        .active_count
                                        .write()
                                        .unwrap();
                                    *surplus_count -= 1;
                                }

                                #[cfg(feature = "store_unexpected")]
                                let addr = result.0.clone();

                                let _read_result = server.read_next_bytes(result).await;

                                #[cfg(feature = "store_unexpected")]
                                if _read_result.is_unexpected() {
                                    let _ = server.store_unexpected_errors.error_sender.send(UnexpectedError::OfReadAddrBytes(addr, _read_result)).await;
                                } 
                            }
                            Err(_) => {
                                if was_used {
                                    was_used = false;
                                    let mut surplus_count = server
                                        .read_handler_properties
                                        .active_count
                                        .write()
                                        .unwrap();
                                    *surplus_count += 1;
                                }
                            }
                        }
                    } else {
                        break 'l1;
                    }
                }
            } else {
                break 'l1;
            }
        }
    }
}