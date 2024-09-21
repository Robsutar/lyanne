use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    time::Instant,
};

use crate::{
    internal::{messages::{
        DeserializedMessage, MessageId, MessagePart, MessagePartId,
        MessagePartMapTryInsertResult, MessagePartMapTryReadResult
    }, MessageChannel},
    packets::{
        SerializedPacket, SerializedPacketList,
    },
    internal::rt::TaskHandle,
};

use super::*;

pub mod server {
    use super::*;

    pub async fn create_receiving_bytes_handler(
        client: Weak<ClientInternal>,
        server: Weak<ConnectedServer>,
        receiving_bytes_receiver: async_channel::Receiver<Vec<u8>>,
    ) {
        'l1: while let Ok(bytes) = receiving_bytes_receiver.recv().await {
            if let Some(client) = ClientInternal::try_upgrade(&client) {
                if let Some(server) = server.upgrade() {
                    let mut messaging = server.messaging.lock().await;
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
                                        &client.messaging_properties.packet_loss_rtt_properties,
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
                                            &client.messaging_properties.packet_loss_rtt_properties,
                                            delay,
                                        );
                                    }
                                }
                            } else {
                                let _ = client
                                    .reason_to_disconnect_sender
                                    .try_send(ServerDisconnectReason::InvalidProtocolCommunication);
                                break 'l1;
                            }
                        }
                        MessageChannel::MESSAGE_PART_SEND => {
                            let message_part_bytes = server.inner_auth.extract_after_channel(&bytes);

                            let message_part_bytes = match message_part_bytes {
                                Ok(message_part_bytes) => message_part_bytes,
                                Err(_) => {
                                    let _ = client
                                        .reason_to_disconnect_sender
                                        .try_send(ServerDisconnectReason::InvalidProtocolCommunication);
                                    break 'l1;
                                }
                            };

                            if let Ok(part) = MessagePart::deserialize(message_part_bytes) {
                                let mut send_fully_message_confirmation = false;
                                let message_id = part.message_id();
                                let part_id = part.id();

                                match messaging.incoming_messages.try_insert(part) {
                                    MessagePartMapTryInsertResult::PastMessageId => {
                                        let _ = server
                                            .message_part_confirmation_sender
                                            .try_send((message_id, None));
                                    },
                                    MessagePartMapTryInsertResult::Stored => {
                                        'l2: loop {
                                            match messaging.incoming_messages.try_read(&client.packet_registry){
                                                MessagePartMapTryReadResult::PendingParts => break 'l2,
                                                MessagePartMapTryReadResult::ErrorInCompleteMessageDeserialize(_) => {
                                                    let _ = client.reason_to_disconnect_sender.try_send(
                                                        ServerDisconnectReason::InvalidProtocolCommunication,
                                                    );
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
                                            let _ = server
                                                .message_part_confirmation_sender
                                                .try_send((message_id, None));
                                        } else {
                                            let _ = server
                                                .message_part_confirmation_sender
                                                .try_send((message_id, Some(part_id)));
                                        }
                                    },
                                }

                                *server.incoming_messages_total_size.write().unwrap() = messaging.incoming_messages.total_size();
                            } else {
                                let _ = client.reason_to_disconnect_sender.try_send(
                                    ServerDisconnectReason::InvalidProtocolCommunication
                                );
                                break 'l1;
                            }
                        }
                        MessageChannel::REJECTION_JUSTIFICATION => {
                            let justification_bytes = server.inner_auth.extract_after_channel(&bytes);

                            let justification_bytes = match justification_bytes {
                                Ok(justification_bytes) => justification_bytes,
                                Err(_) => {
                                    let _ = client
                                        .reason_to_disconnect_sender
                                        .try_send(ServerDisconnectReason::InvalidProtocolCommunication);
                                    break 'l1;
                                }
                            };

                            if let Ok(message) =
                                DeserializedMessage::deserialize_single_list(&justification_bytes, &client.packet_registry)
                            {
                                let _ = client.socket.send(&vec![MessageChannel::REJECTION_CONFIRM]).await;
                                
                                let _ = client
                                    .reason_to_disconnect_sender
                                    .try_send(ServerDisconnectReason::DisconnectRequest(message));
                                break 'l1;
                            } else {
                                let _ = client
                                    .reason_to_disconnect_sender
                                    .try_send(ServerDisconnectReason::InvalidProtocolCommunication);
                                break 'l1;
                            }
                        }
                        _ => {
                            let _ = client
                                .reason_to_disconnect_sender
                                .try_send(ServerDisconnectReason::InvalidProtocolCommunication);
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
        client: Weak<ClientInternal>,
        server: Weak<ConnectedServer>,
        packets_to_send_receiver: async_channel::Receiver<Option<SerializedPacket>>,
        mut next_message_id: MessagePartId,
    ) {
        let mut packets_to_send: Vec<SerializedPacket> = Vec::new();

        'l1: while let Ok(serialized_packet) = packets_to_send_receiver.recv().await {
            if let Some(serialized_packet) = serialized_packet {
                packets_to_send.push(serialized_packet);
            } else {
                if let Some(client) = ClientInternal::try_upgrade(&client) {
                    if let Some(server) = server.upgrade() {
                        let mut messaging = server.messaging.lock().await;
                        let packets_to_send = std::mem::replace(&mut packets_to_send, Vec::new());

                        let bytes = SerializedPacketList::try_non_empty(packets_to_send).unwrap().bytes;
                        let message_parts = MessagePart::create_list(
                            &client.messaging_properties,
                            next_message_id,
                            bytes,
                        )
                        .unwrap();

                        let sent_instant = Instant::now();

                        for part in message_parts {
                            let part_id: u16 = part.id();
                            let part_message_id = part.message_id();
                            
                            let sent_part = server.inner_auth.sent_part_of(sent_instant, part);

                            let finished_bytes = Arc::clone(&sent_part.finished_bytes);

                            let (_, pending_part_id_map) = messaging
                                .pending_confirmation
                                .entry(part_message_id)
                                .or_insert_with(|| (sent_instant, BTreeMap::new()));
                            pending_part_id_map.insert(part_id, sent_part);

                            let _ = server
                                .shared_socket_bytes_send_sender
                                .try_send(finished_bytes);
                        }

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

    pub async fn create_message_part_confirmation_handler(
        client: Weak<ClientInternal>,
        message_part_confirmation_receiver: async_channel::Receiver<(
            MessageId,
            Option<MessagePartId>,
        )>,
    ) {
        'l1: while let Ok((message_id, part_id)) = message_part_confirmation_receiver.recv().await {
            if let Some(client) = ClientInternal::try_upgrade(&client) {
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
                if let Err(e) = client.socket.send(&bytes).await {
                    let _ = client
                        .reason_to_disconnect_sender
                        .try_send(ServerDisconnectReason::ByteSendError(e));
                    break 'l1;
                }
            } else {
                break 'l1;
            }
        }
    }

    pub async fn create_shared_socket_bytes_send_handler(
        client: Weak<ClientInternal>,
        shared_socket_bytes_send_receiver: async_channel::Receiver<Arc<Vec<u8>>>,
    ) {
        'l1: while let Ok(bytes) = shared_socket_bytes_send_receiver.recv().await {
            if let Some(client) = ClientInternal::try_upgrade(&client) {
                if let Err(e) = client.socket.send(&bytes).await {
                    let _ = client
                        .reason_to_disconnect_sender
                        .try_send(ServerDisconnectReason::ByteSendError(e));
                    break 'l1;
                }
            } else {
                break 'l1;
            }
        }
    }
}

pub mod client {

    use super::*;

    #[cfg(feature = "rt_tokio")]
    pub async fn create_async_tasks_keeper(
        tasks_keeper_receiver: async_channel::Receiver<TaskHandle<()>>,
    ) {
        while let Ok(handle) = tasks_keeper_receiver.recv().await {
            let _ = handle.await;
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

    #[cfg(feature = "store_unexpected")]
    pub async fn store_unexpected_error_list_pick(client: &ClientInternal) -> Vec<UnexpectedError> {
        let mut list = Vec::<UnexpectedError>::new();
        while let Ok(mut error_list) = client.store_unexpected_errors.error_list_receiver.try_recv() {
            list.append(&mut error_list);
        }
        while let Ok(error) = client.store_unexpected_errors.error_receiver.try_recv() {
            list.push(error);
        }

        list
    }

    #[cfg(feature = "store_unexpected")]
    pub async fn create_store_unexpected_error_list_handler(
        client: Weak<ClientInternal>,
        create_list_signal_receiver: async_channel::Receiver<()>,
    ) {
        'l1: while let Ok(_) = create_list_signal_receiver.recv().await {
            if let Some(client) = ClientInternal::try_upgrade(&client) {                
                let _ = client.store_unexpected_errors.error_list_sender.send(store_unexpected_error_list_pick(&client).await).await;
            } else {
                break 'l1;
            }
        }
    }

    pub async fn create_read_handler(weak_client: Weak<ClientInternal>) {
        let mut was_used = false;
        'l1: loop {
            if let Some(client) = ClientInternal::try_upgrade(&weak_client) {
                if *client.read_handler_properties.active_count.write().unwrap()
                    > client.read_handler_properties.target_surplus_size + 1
                {
                    let mut surplus_count =
                        client.read_handler_properties.active_count.write().unwrap();
                    if !was_used {
                        *surplus_count -= 1;
                    }
                    break 'l1;
                } else {
                    let read_timeout = client.messaging_properties.timeout_interpretation;
                    let socket = Arc::clone(&client.socket);
                    drop(client);
                    let pre_read_next_bytes_result =
                        ClientInternal::pre_read_next_bytes(&socket, read_timeout).await;
                    match ClientInternal::try_upgrade_or_get_inactive(&weak_client).await {
                        Some(Ok(client)) => {
                            match pre_read_next_bytes_result {
                                Ok(result) => {
                                    if !was_used {
                                        was_used = true;
                                        let mut surplus_count = client
                                            .read_handler_properties
                                            .active_count
                                            .write()
                                            .unwrap();
                                        *surplus_count -= 1;
                                    }

                                    let _read_result = client.read_next_bytes(result).await;

                                    #[cfg(feature = "store_unexpected")]
                                    if _read_result.is_unexpected() {
                                        let _ = client.store_unexpected_errors.error_sender.send(UnexpectedError::OfReadServerBytes(_read_result)).await;
                                    }
                                }
                                Err(_) => {
                                    if was_used {
                                        was_used = false;
                                        let mut surplus_count = client
                                            .read_handler_properties
                                            .active_count
                                            .write()
                                            .unwrap();
                                        *surplus_count += 1;
                                    }
                                }
                            }
                        }
                        Some(Err(inactive_state)) => {
                            if let Ok(result) =  pre_read_next_bytes_result {
                                let _ = inactive_state.received_bytes_sender.try_send(result);
                            }
                            break 'l1;
                        }
                        None => {
                            break 'l1;
                        }
                    }
                }
            } else {
                break 'l1;
            }
        }
    }
}
