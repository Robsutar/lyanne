use std::sync::{Arc, Weak};

use crate::{
    internal::rt::TaskHandle,
    internal::{
        messages::{MessageId, MessagePartId},
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
            println!("Client receiving bytes: {:?} ", bytes);
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
                            println!("Client sending rejection confirm");
                            let x = node
                                .socket
                                .send(&vec![MessageChannel::REJECTION_CONFIRM])
                                .await;
                            println!("Result of send: {:?}", x);

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

                        let serialized_packet_list =
                            SerializedPacketList::try_non_empty(packets_to_send).unwrap();
                        NodeType::push_completed_message_tick(
                            &node,
                            &server,
                            &mut messaging,
                            &server.shared_socket_bytes_send_sender,
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
    pub async fn create_store_unexpected_error_list_handler(
        node: Weak<NodeInternal<ClientNode>>,
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
