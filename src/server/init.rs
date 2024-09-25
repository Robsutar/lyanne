use std::{
    net::SocketAddr,
    sync::{Arc, Weak},
    time::Instant,
};

use crate::{
    internal::{
        messages::{MessageId, MessagePartId},
        rt::TaskHandle,
        MessageChannel,
    },
    packets::{SerializedPacket, SerializedPacketList},
};

use super::*;

pub mod client {
    use crate::internal::node::ReceivedBytesProcessResult;

    use super::*;

    pub async fn create_receiving_bytes_handler(
        node: Weak<NodeInternal<ServerNode>>,
        addr: SocketAddr,
        client: Weak<ConnectedClient>,
        receiving_bytes_receiver: async_channel::Receiver<Vec<u8>>,
    ) {
        'l1: while let Ok(bytes) = receiving_bytes_receiver.recv().await {
            if let Some(node) = NodeInternal::try_upgrade(&node) {
                if let Some(client) = client.upgrade() {
                    match NodeType::handle_received_bytes(&node, &client, bytes).await {
                        ReceivedBytesProcessResult::InvalidProtocolCommunication => {
                            let _ = node.node_type.clients_to_disconnect_sender.try_send((
                                addr,
                                (ClientDisconnectReason::InvalidProtocolCommunication, None),
                            ));
                            break 'l1;
                        }
                        ReceivedBytesProcessResult::AuthMessage(_bytes) => {
                            // Client probably multiple authentication packets before being authenticated
                        }
                        ReceivedBytesProcessResult::RejectionJustification(message) => {
                            node.node_type
                                .recently_disconnected
                                .insert(addr, Instant::now());
                            node.node_type.rejections_to_confirm.insert(addr);

                            let _ = node.node_type.clients_to_disconnect_sender.try_send((
                                addr,
                                (ClientDisconnectReason::DisconnectRequest(message), None),
                            ));
                            break 'l1;
                        }
                        ReceivedBytesProcessResult::MessagePartConfirm
                        | ReceivedBytesProcessResult::MessagePartSent => (),
                    }
                }
            } else {
                break 'l1;
            }
        }
    }

    pub async fn create_packets_to_send_handler(
        node: Weak<NodeInternal<ServerNode>>,
        client: Weak<ConnectedClient>,
        packets_to_send_receiver: async_channel::Receiver<Option<SerializedPacket>>,
        mut next_message_id: MessagePartId,
    ) {
        let mut packets_to_send: Vec<SerializedPacket> = Vec::new();

        'l1: while let Ok(serialized_packet) = packets_to_send_receiver.recv().await {
            if let Some(serialized_packet) = serialized_packet {
                packets_to_send.push(serialized_packet);
            } else {
                if let Some(node) = NodeInternal::try_upgrade(&node) {
                    if let Some(client) = client.upgrade() {
                        let mut messaging = client.messaging.lock().await;
                        let packets_to_send = std::mem::replace(&mut packets_to_send, Vec::new());

                        let serialized_packet_list =
                            SerializedPacketList::try_non_empty(packets_to_send).unwrap();
                        NodeType::push_completed_message_tick(
                            &node,
                            &client,
                            &mut messaging,
                            &client.shared_socket_bytes_send_sender,
                            next_message_id,
                            serialized_packet_list,
                        );

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
        node: Weak<NodeInternal<ServerNode>>,
        addr: SocketAddr,
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
                if let Err(e) = node.socket.send_to(&bytes, addr).await {
                    let _ = node
                        .node_type
                        .clients_to_disconnect_sender
                        .try_send((addr, (ClientDisconnectReason::ByteSendError(e), None)));
                    break 'l1;
                }
            } else {
                break 'l1;
            }
        }
    }

    pub async fn create_shared_socket_bytes_send_handler(
        node: Weak<NodeInternal<ServerNode>>,
        addr: SocketAddr,
        shared_socket_bytes_send_receiver: async_channel::Receiver<Arc<Vec<u8>>>,
    ) {
        'l1: while let Ok(bytes) = shared_socket_bytes_send_receiver.recv().await {
            if let Some(node) = NodeInternal::try_upgrade(&node) {
                if let Err(e) = node.socket.send_to(&bytes, addr).await {
                    let _ = node
                        .node_type
                        .clients_to_disconnect_sender
                        .try_send((addr, (ClientDisconnectReason::ByteSendError(e), None)));
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

    pub async fn create_pending_rejection_confirm_resend_handler(
        node: Weak<NodeInternal<ServerNode>>,
        pending_rejection_confirm_resend_receiver: async_channel::Receiver<SocketAddr>,
    ) {
        'l1: while let Ok(addr) = pending_rejection_confirm_resend_receiver.recv().await {
            if let Some(node) = NodeInternal::try_upgrade(&node) {
                if let Some(mut tuple) = node.node_type.pending_rejection_confirm.get_mut(&addr) {
                    let (context, last_sent_time) = tuple.value_mut();
                    *last_sent_time = Some(Instant::now());
                    let _ = node.socket.send_to(&context.finished_bytes, addr).await;
                }
            } else {
                break 'l1;
            }
        }
    }

    pub async fn create_rejections_to_confirm_handler(
        node: Weak<NodeInternal<ServerNode>>,
        rejections_to_confirm_signal_receiver: async_channel::Receiver<()>,
    ) {
        let rejection_confirm_bytes = &vec![MessageChannel::REJECTION_CONFIRM];
        'l1: while let Ok(_) = rejections_to_confirm_signal_receiver.recv().await {
            if let Some(node) = NodeInternal::try_upgrade(&node) {
                for addr in node.node_type.rejections_to_confirm.iter() {
                    let _ = node.socket.send_to(rejection_confirm_bytes, *addr).await;
                }
                node.node_type.rejections_to_confirm.clear();
            } else {
                break 'l1;
            }
        }
    }

    #[cfg(feature = "store_unexpected")]
    pub async fn create_store_unexpected_error_list_handler(
        node: Weak<NodeInternal<ServerNode>>,
        create_list_signal_receiver: async_channel::Receiver<()>,
    ) {
        'l1: while let Ok(_) = create_list_signal_receiver.recv().await {
            if let Some(node) = NodeInternal::try_upgrade(&node) {
                let _ = node
                    .store_unexpected_errors
                    .error_list_sender
                    .send(NodeType::store_unexpected_error_list_pick(&node).await)
                    .await;
            } else {
                break 'l1;
            }
        }
    }
}
