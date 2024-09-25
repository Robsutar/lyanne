use std::{
    collections::BTreeMap,
    sync::{Arc, Weak},
    time::Instant,
};

use crate::{
    internal::rt::TaskHandle,
    internal::{
        messages::{MessageId, MessagePart, MessagePartId},
        MessageChannel,
    },
    packets::{SerializedPacket, SerializedPacketList},
};

use super::*;

pub mod server {
    use crate::internal::node::ReceivedBytesProcessResult;

    use super::*;

    pub async fn create_receiving_bytes_handler(
        node: Weak<NodeInternal<ClientNode>>,
        server: Weak<ConnectedServer>,
        receiving_bytes_receiver: async_channel::Receiver<Vec<u8>>,
    ) {
        'l1: while let Ok(bytes) = receiving_bytes_receiver.recv().await {
            if let Some(node) = NodeInternal::try_upgrade(&node) {
                if let Some(server) = server.upgrade() {
                    match NodeType::handle_received_bytes(&node, &server, bytes).await {
                        ReceivedBytesProcessResult::InvalidProtocolCommunication
                        | ReceivedBytesProcessResult::AuthMessage(_) => {
                            let _ = node
                                .node_type
                                .reason_to_disconnect_sender
                                .try_send(ServerDisconnectReason::InvalidProtocolCommunication);
                            break 'l1;
                        }
                        ReceivedBytesProcessResult::RejectionJustification(message) => {
                            let _ = node
                                .socket
                                .send(&vec![MessageChannel::REJECTION_CONFIRM])
                                .await;

                            let _ = node
                                .node_type
                                .reason_to_disconnect_sender
                                .try_send(ServerDisconnectReason::DisconnectRequest(message));
                            break 'l1;
                        }
                        ReceivedBytesProcessResult::MessagePartConfirm
                        | ReceivedBytesProcessResult::MessagePartSent => (),
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
        node: Weak<NodeInternal<ClientNode>>,
        server: Weak<ConnectedServer>,
        packets_to_send_receiver: async_channel::Receiver<Option<SerializedPacket>>,
        mut next_message_id: MessagePartId,
    ) {
        let mut packets_to_send: Vec<SerializedPacket> = Vec::new();

        'l1: while let Ok(serialized_packet) = packets_to_send_receiver.recv().await {
            if let Some(serialized_packet) = serialized_packet {
                packets_to_send.push(serialized_packet);
            } else {
                if let Some(node) = NodeInternal::try_upgrade(&node) {
                    if let Some(server) = server.upgrade() {
                        let mut messaging = server.messaging.lock().await;
                        let packets_to_send = std::mem::replace(&mut packets_to_send, Vec::new());

                        let bytes = SerializedPacketList::try_non_empty(packets_to_send)
                            .unwrap()
                            .bytes;
                        let message_parts = MessagePart::create_list(
                            &node.messaging_properties,
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
        node: Weak<NodeInternal<ClientNode>>,
        message_part_confirmation_receiver: async_channel::Receiver<(
            MessageId,
            Option<MessagePartId>,
        )>,
    ) {
        'l1: while let Ok((message_id, part_id)) = message_part_confirmation_receiver.recv().await {
            if let Some(node) = NodeInternal::try_upgrade(&node) {
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
                if let Err(e) = node.socket.send(&bytes).await {
                    let _ = node
                        .node_type
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
        node: Weak<NodeInternal<ClientNode>>,
        shared_socket_bytes_send_receiver: async_channel::Receiver<Arc<Vec<u8>>>,
    ) {
        'l1: while let Ok(bytes) = shared_socket_bytes_send_receiver.recv().await {
            if let Some(node) = NodeInternal::try_upgrade(&node) {
                if let Err(e) = node.socket.send(&bytes).await {
                    let _ = node
                        .node_type
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
    pub async fn store_unexpected_error_list_pick(
        node: &NodeInternal<ClientNode>,
    ) -> Vec<UnexpectedError> {
        let mut list = Vec::<UnexpectedError>::new();
        while let Ok(mut error_list) = node
            .node_type
            .store_unexpected_errors
            .error_list_receiver
            .try_recv()
        {
            list.append(&mut error_list);
        }
        while let Ok(error) = node
            .node_type
            .store_unexpected_errors
            .error_receiver
            .try_recv()
        {
            list.push(error);
        }

        list
    }

    #[cfg(feature = "store_unexpected")]
    pub async fn create_store_unexpected_error_list_handler(
        node: Weak<NodeInternal<ClientNode>>,
        create_list_signal_receiver: async_channel::Receiver<()>,
    ) {
        'l1: while let Ok(_) = create_list_signal_receiver.recv().await {
            if let Some(node) = NodeInternal::try_upgrade(&node) {
                let _ = node
                    .node_type
                    .store_unexpected_errors
                    .error_list_sender
                    .send(store_unexpected_error_list_pick(&node).await)
                    .await;
            } else {
                break 'l1;
            }
        }
    }
}
