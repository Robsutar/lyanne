use std::{collections::BTreeMap, io};

use crate::{
    packets::{DeserializedPacket, PacketRegistry},
    transport::{MessageChannel, MessagingProperties},
    utils::ORDERED_ROTATABLE_U8_VEC_MAX_SIZE,
};

pub type MessagePartId = u8;
pub type MessagePartLargeId = u16;
pub type MessagePartType = u8;
pub const MESSAGE_PART_SERIALIZED_SIZE: usize = 1024;

struct MessagePartTypes;

impl MessagePartTypes {
    pub const SINGLE: MessagePartType = 252;
    pub const START: MessagePartType = 253;
    pub const CENTER: MessagePartType = 254;
    pub const END: MessagePartType = 255;
}

pub struct MessagePart {
    bytes: Vec<u8>,
}

impl MessagePart {
    pub fn new(id: MessagePartId, part_type: MessagePartType, content: Vec<u8>) -> Self {
        let mut bytes = Vec::with_capacity(2 + content.len());
        bytes.push(id);
        bytes.push(part_type);
        bytes.extend(content);
        Self { bytes }
    }
    pub fn deserialize(bytes: Vec<u8>) -> io::Result<Self> {
        if bytes.len() < 3 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Bytes are not sufficiently large",
            ));
        }
        let exit = Self { bytes };
        Ok(exit)
    }
    pub fn id(&self) -> MessagePartId {
        self.bytes[0]
    }
    pub fn part_type(&self) -> MessagePartType {
        self.bytes[1]
    }
    pub fn content(&self) -> &[u8] {
        &self.bytes[2..]
    }
    pub fn take_content(mut self) -> Vec<u8> {
        self.bytes.drain(..2);
        self.bytes
    }
    pub fn clone_bytes_with_channel(&self) -> Vec<u8> {
        let mut exit = Vec::with_capacity(self.bytes.len() + 1);
        exit.push(MessageChannel::MESSAGE_PART_SEND);
        exit.extend_from_slice(&self.bytes);
        exit
    }
}

impl MessagePart {
    pub fn create_list(
        mut complete_message: Vec<u8>,
        props: &MessagingProperties,
        first_id: MessagePartId,
    ) -> io::Result<Vec<MessagePart>> {
        if complete_message.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Empty complete message",
            ));
        }

        let part_limit = props.part_limit;

        let num_parts = (complete_message.len() as f32 / part_limit as f32).ceil() as usize;
        if num_parts > ORDERED_ROTATABLE_U8_VEC_MAX_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Number of parts {:?} reached the limit of {:?}",
                    num_parts, ORDERED_ROTATABLE_U8_VEC_MAX_SIZE
                ),
            ));
        }

        if num_parts == 1 {
            return Ok(vec![MessagePart::new(
                first_id,
                MessagePartTypes::SINGLE,
                complete_message,
            )]);
        }

        let mut parts = Vec::with_capacity(num_parts);

        let mut current_id = first_id;

        while complete_message.len() > part_limit {
            let part_data = complete_message.split_off(part_limit);
            let part_type = if parts.is_empty() {
                MessagePartTypes::START
            } else {
                MessagePartTypes::CENTER
            };
            parts.push(MessagePart::new(current_id, part_type, complete_message));
            complete_message = part_data;
            current_id = current_id.wrapping_add(1);
        }

        let part_type = if parts.is_empty() {
            MessagePartTypes::SINGLE
        } else {
            MessagePartTypes::END
        };
        parts.push(MessagePart::new(current_id, part_type, complete_message));

        Ok(parts)
    }
}

pub struct DeserializedMessageCheck {
    kind: DeserializedMessageCheckKind,
}

enum DeserializedMessageCheckKind {
    Single,
    EndConfirmed,
    InvalidStartType(MessagePartType),
    InvalidEndType(MessagePartType),
}

impl DeserializedMessageCheck {
    pub fn new(
        tree: &BTreeMap<MessagePartLargeId, MessagePart>,
    ) -> io::Result<DeserializedMessageCheck> {
        if tree.is_empty() {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "Empty vec"));
        }
        let (_, first) = &tree.first_key_value().unwrap();

        match first.part_type() {
            MessagePartTypes::SINGLE => {
                if tree.len() == 1 {
                    return Ok(DeserializedMessageCheck {
                        kind: DeserializedMessageCheckKind::Single,
                    });
                }
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Size of single, but is not a single part",
                ));
            }
            MessagePartTypes::START => {
                if tree.len() < 2 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!("START message part is end, but at least 2 parts are needed, size returned: {:?}", tree.len())
                    ));
                }

                let (_, last) = &tree.last_key_value().unwrap();
                match last.part_type() {
                    MessagePartTypes::SINGLE => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Last part is SINGLE, but should be END",
                        ));
                    }
                    MessagePartTypes::START => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Last part is START, but should be END",
                        ));
                    }
                    MessagePartTypes::CENTER => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "Last part is CENTER, but should be END",
                        ));
                    }
                    MessagePartTypes::END => {}
                    part_type => {
                        return Ok(DeserializedMessageCheck {
                            kind: DeserializedMessageCheckKind::InvalidEndType(part_type),
                        });
                    }
                }

                let diff = first.id().wrapping_add(tree.len() as u8).wrapping_sub(1);

                if diff != last.id() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "The size of the message parts ({:?}) did not match, target diff: {:?}, last id: {:?}",
                            tree.len(), diff, last.id()
                        ),
                    ));
                }

                return Ok(DeserializedMessageCheck {
                    kind: DeserializedMessageCheckKind::EndConfirmed,
                });
            }
            MessagePartTypes::CENTER => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "First part is CENTER, but should be START or SINGLE",
                ));
            }
            MessagePartTypes::END => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "First part is END, but should be SINGLE or START",
                ));
            }
            part_type => {
                return Ok(DeserializedMessageCheck {
                    kind: DeserializedMessageCheckKind::InvalidStartType(part_type),
                });
            }
        }
    }
}

#[derive(Debug)]
pub struct DeserializedMessage {
    pub packets: Vec<DeserializedPacket>,
}

impl DeserializedMessage {
    pub fn deserialize(
        packet_registry: &PacketRegistry,
        check: DeserializedMessageCheck,
        tree: BTreeMap<MessagePartLargeId, MessagePart>,
    ) -> io::Result<Self> {
        match check.kind {
            DeserializedMessageCheckKind::Single => {
                let (_, last) = &tree.last_key_value().unwrap();
                return Ok(DeserializedMessage {
                    packets: DeserializedPacket::deserialize_list(
                        last.content(),
                        &packet_registry,
                    )?,
                });
            }

            DeserializedMessageCheckKind::EndConfirmed => {
                let total_capacity: usize = tree
                    .iter()
                    .map(|(_, part)| part.bytes.len().saturating_sub(2))
                    .sum();
                let mut unified_messages: Vec<u8> = Vec::with_capacity(total_capacity);

                for (_, part) in tree {
                    let mut content = part.take_content();
                    unified_messages.append(&mut content);
                }
                return Ok(DeserializedMessage {
                    packets: DeserializedPacket::deserialize_list(
                        &unified_messages,
                        &packet_registry,
                    )?,
                });
            }
            DeserializedMessageCheckKind::InvalidStartType(part_type) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid start type {:?}", part_type),
                ));
            }
            DeserializedMessageCheckKind::InvalidEndType(part_type) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("Invalid end type {:?}", part_type),
                ));
            }
        }
    }
}
