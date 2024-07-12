use std::{collections::BTreeMap, io};

use crate::{
    packets::{DeserializedPacket, PacketRegistry},
    transport::MessagingProperties,
};

pub type MessagePartId = u16;
pub type MessagePartType = u8;

pub const MESSAGE_PART_ID_SIZE: usize = size_of::<MessagePartId>();
pub const MESSAGE_PART_TYPE_SIZE: usize = size_of::<MessagePartType>();

pub const MAX_MESSAGE_PART_SIZE: MessagePartId = MessagePartId::MAX / 2;
pub const MAX_MESSAGE_PART_SIZE_USIZE: usize = MessagePartId::MAX as usize / 2;

struct MessagePartTypes;

impl MessagePartTypes {
    pub const SINGLE: MessagePartType = 252;
    pub const START: MessagePartType = 253;
    pub const CENTER: MessagePartType = 254;
    pub const END: MessagePartType = 255;
}

#[derive(Debug)]
pub struct MessagePart {
    bytes: Vec<u8>,
}

impl MessagePart {
    pub fn new(id: MessagePartId, part_type: MessagePartType, content: Vec<u8>) -> Self {
        let mut bytes = Vec::with_capacity(2 + content.len());
        bytes.extend(id.to_le_bytes());
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
        MessagePartId::from_le_bytes([self.bytes[0], self.bytes[1]])
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn to_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub fn part_type(&self) -> MessagePartType {
        self.bytes[2]
    }
    pub fn content(&self) -> &[u8] {
        &self.bytes[3..]
    }
    pub fn take_content(mut self) -> Vec<u8> {
        self.bytes.drain(..3);
        self.bytes
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

        let part_limit = props.part_limit - MESSAGE_PART_ID_SIZE - MESSAGE_PART_TYPE_SIZE;

        let num_parts = (complete_message.len() as f32 / part_limit as f32).ceil() as usize;
        if num_parts > MAX_MESSAGE_PART_SIZE_USIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Number of parts {:?} reached the limit of {:?}",
                    num_parts, MAX_MESSAGE_PART_SIZE_USIZE
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
            current_id = current_id + 1;
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
        tree: &BTreeMap<MessagePartId, MessagePart>,
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

                let diff = first.id() + (tree.len() as MessagePartId) - 1;

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
        tree: BTreeMap<MessagePartId, MessagePart>,
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

pub enum MessagePartMapTryInsertResult {
    NotInBounds,
    Stored,
    ErrorInCompleteMessageDeserialize(std::io::Error),
    SuccessfullyCreated(DeserializedMessage),
}

pub struct MessagePartMap {
    map: BTreeMap<MessagePartId, MessagePart>,
    next_message_to_receive_start_id: MessagePartId,
}

impl MessagePartMap {
    pub fn new(next_message_to_receive_start_id: MessagePartId) -> Self {
        Self {
            map: BTreeMap::new(),
            next_message_to_receive_start_id,
        }
    }
    pub fn try_insert(
        &mut self,
        packet_registry: &PacketRegistry,
        part: MessagePart,
    ) -> MessagePartMapTryInsertResult {
        let part_id = part.id();
        if part_id >= self.next_message_to_receive_start_id {
            self.map.insert(part_id, part);
            if let Ok(check) = DeserializedMessageCheck::new(&self.map) {
                let completed_parts = std::mem::replace(&mut self.map, BTreeMap::new());
                let new_next_message_to_receive_start_id =
                    next_message_to_receive_start_id(*completed_parts.last_key_value().unwrap().0);

                self.next_message_to_receive_start_id = new_next_message_to_receive_start_id;
                match DeserializedMessage::deserialize(packet_registry, check, completed_parts) {
                    Ok(message) => MessagePartMapTryInsertResult::SuccessfullyCreated(message),
                    Err(e) => MessagePartMapTryInsertResult::ErrorInCompleteMessageDeserialize(e),
                }
            } else {
                MessagePartMapTryInsertResult::Stored
            }
        } else {
            MessagePartMapTryInsertResult::NotInBounds
        }
    }
}

pub fn next_message_to_receive_start_id(last_id: MessagePartId) -> MessagePartId {
    let new_next_message_to_receive_start_id = {
        if last_id > MAX_MESSAGE_PART_SIZE {
            0
        } else {
            last_id + 1
        }
    };
    new_next_message_to_receive_start_id
}
