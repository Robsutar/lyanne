use std::{collections::BTreeMap, io};

use crate::{
    packets::{DeserializedPacket, PacketRegistry},
    transport::MessagingProperties,
};

pub type MessageId = u16;
pub type MessagePartId = u16;
pub type MessagePartType = u8;

pub const MESSAGE_ID_SIZE: usize = size_of::<MessageId>();
pub const MESSAGE_PART_ID_SIZE: usize = size_of::<MessagePartId>();
pub const MESSAGE_PART_TYPE_SIZE: usize = size_of::<MessagePartType>();

pub const MAX_STORABLE_MESSAGE_COUNT: MessageId = MessageId::MAX / 2;

pub const MINIMAL_PART_BYTES_SIZE: usize = 5;

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
    pub fn new(
        message_id: MessageId,
        id: MessagePartId,
        part_type: MessagePartType,
        content: Vec<u8>,
    ) -> Self {
        let mut bytes = Vec::with_capacity(2 + content.len());
        bytes.extend(message_id.to_le_bytes());
        bytes.extend(id.to_le_bytes());
        bytes.push(part_type);
        bytes.extend(content);
        Self { bytes }
    }
    pub fn deserialize(bytes: Vec<u8>) -> io::Result<Self> {
        if bytes.len() < MINIMAL_PART_BYTES_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Bytes are not sufficiently large",
            ));
        }
        let exit = Self { bytes };
        Ok(exit)
    }
    pub fn message_id(&self) -> MessageId {
        MessageId::from_le_bytes([self.bytes[0], self.bytes[1]])
    }
    pub fn id(&self) -> MessagePartId {
        MessagePartId::from_le_bytes([self.bytes[2], self.bytes[3]])
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn to_bytes(self) -> Vec<u8> {
        self.bytes
    }
    pub fn part_type(&self) -> MessagePartType {
        self.bytes[4]
    }
    pub fn content(&self) -> &[u8] {
        &self.bytes[5..]
    }
    pub fn take_content(mut self) -> Vec<u8> {
        self.bytes.drain(..5);
        self.bytes
    }
}

impl MessagePart {
    pub fn create_list(
        props: &MessagingProperties,
        message_id: MessageId,
        mut complete_message: Vec<u8>,
    ) -> io::Result<Vec<MessagePart>> {
        if complete_message.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Empty complete message",
            ));
        }

        let part_limit =
            props.part_limit - MESSAGE_ID_SIZE - MESSAGE_PART_ID_SIZE - MESSAGE_PART_TYPE_SIZE;

        let num_parts = (complete_message.len() as f32 / part_limit as f32).ceil() as usize;
        if num_parts > MessagePartId::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "Number of parts {:?} reached the limit of {:?}",
                    num_parts,
                    MessagePartId::MAX as usize
                ),
            ));
        }

        if num_parts == 1 {
            return Ok(vec![MessagePart::new(
                message_id,
                0,
                MessagePartTypes::SINGLE,
                complete_message,
            )]);
        }

        let mut parts = Vec::with_capacity(num_parts);

        let mut current_id = 0;

        while complete_message.len() > part_limit {
            let part_data = complete_message.split_off(part_limit);
            let part_type = if parts.is_empty() {
                MessagePartTypes::START
            } else {
                MessagePartTypes::CENTER
            };
            parts.push(MessagePart::new(
                message_id,
                current_id,
                part_type,
                complete_message,
            ));
            complete_message = part_data;
            current_id = current_id + 1;
        }

        let part_type = if parts.is_empty() {
            MessagePartTypes::SINGLE
        } else {
            MessagePartTypes::END
        };
        parts.push(MessagePart::new(
            message_id,
            current_id,
            part_type,
            complete_message,
        ));

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
    PastMessageId,
    Stored,
}

pub enum MessagePartMapTryReadResult {
    PendingParts,
    ErrorInCompleteMessageDeserialize(std::io::Error),
    SuccessfullyCreated(DeserializedMessage),
}

pub struct MessagePartMap {
    pub next_message_id: MessageId,
    pub maps: BTreeMap<MessageId, (BTreeMap<MessagePartId, MessagePart>, usize)>,
}

impl MessagePartMap {
    pub fn new(initial_next_message_id: MessagePartId) -> Self {
        Self {
            next_message_id: initial_next_message_id,
            maps: BTreeMap::new(),
        }
    }
    pub fn try_insert(&mut self, part: MessagePart) -> MessagePartMapTryInsertResult {
        let part_message_id = part.message_id();
        if part_message_id < self.next_message_id {
            if self.next_message_id - part_message_id < MAX_STORABLE_MESSAGE_COUNT {
                return MessagePartMapTryInsertResult::PastMessageId;
            }
        } else {
            if part_message_id - self.next_message_id > MAX_STORABLE_MESSAGE_COUNT {
                return MessagePartMapTryInsertResult::PastMessageId;
            }
        }

        let (map, size) = self
            .maps
            .entry(part_message_id)
            .or_insert_with(|| (BTreeMap::new(), 0));

        let part_bytes_len = part.as_bytes().len();

        map.insert(part.id(), part);

        *size += part_bytes_len;
        return MessagePartMapTryInsertResult::Stored;
    }

    pub fn try_read(&mut self, packet_registry: &PacketRegistry) -> MessagePartMapTryReadResult {
        if let Some((map, _)) = self.maps.get(&self.next_message_id) {
            if let Ok(check) = DeserializedMessageCheck::new(map) {
                let (completed_parts, _) = self.maps.remove(&self.next_message_id).unwrap();

                self.next_message_id = self.next_message_id.wrapping_add(1);

                return match DeserializedMessage::deserialize(
                    packet_registry,
                    check,
                    completed_parts,
                ) {
                    Ok(message) => MessagePartMapTryReadResult::SuccessfullyCreated(message),
                    Err(e) => MessagePartMapTryReadResult::ErrorInCompleteMessageDeserialize(e),
                };
            } else {
                MessagePartMapTryReadResult::PendingParts
            }
        } else {
            MessagePartMapTryReadResult::PendingParts
        }
    }

    pub fn total_size(&self) -> usize {
        self.maps.values().map(|(_, size)| size).sum()
    }
}
