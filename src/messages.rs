use std::any::Any;

use crate::{
    collections::{IndexableU8, OrderedRotatableU8Vec, ORDERED_ROTATABLE_U8_VEC_MAX_SIZE},
    packets::{DeserializedPacket, PacketRegistry},
};

pub type MessagePartId = u8;
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
    pub fn deserialize(bytes: Vec<u8>) -> Result<Self, String> {
        if bytes.len() < 3 {
            return Err("Bytes are not larger sufficient".to_owned());
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
}

impl IndexableU8 for MessagePart {
    fn index(&self) -> u8 {
        self.id()
    }
}

impl MessagePart {
    pub fn create_list(
        mut complete_message: Vec<u8>,
        part_limit: usize,
        first_id: MessagePartId,
    ) -> Result<Vec<MessagePart>, String> {
        if complete_message.is_empty() {
            return Ok(Vec::new());
        }

        let num_parts = (complete_message.len() as f32 / part_limit as f32).ceil() as usize;
        if num_parts > ORDERED_ROTATABLE_U8_VEC_MAX_SIZE {
            return Err(format!(
                "Number of parts {:?} reached the limit of {:?}",
                num_parts, ORDERED_ROTATABLE_U8_VEC_MAX_SIZE
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
        vec: &OrderedRotatableU8Vec<MessagePart>,
    ) -> Result<DeserializedMessageCheck, String> {
        let vec_ref = vec.vec_ref();
        if vec_ref.is_empty() {
            return Err("Empty vec".to_string());
        }

        let first = &vec_ref[0];

        match first.part_type() {
            MessagePartTypes::SINGLE => {
                if vec_ref.len() == 1 {
                    return Ok(DeserializedMessageCheck {
                        kind: DeserializedMessageCheckKind::Single,
                    });
                }
                return Err("Size of single, but is not a single part".to_owned());
            }
            MessagePartTypes::START => {
                if vec_ref.len() < 2 {
                    return Err(
                        format!("START message part is end, but at least 2 parts are needed, size returned: {:?}", 
                        vec_ref.len())
                    );
                }

                let last = &vec_ref[vec_ref.len() - 1];
                match last.part_type() {
                    MessagePartTypes::SINGLE => {
                        return Err("Last part is SINGLE, but should be END".to_owned());
                    }
                    MessagePartTypes::START => {
                        return Err("Last part is START, but should be END".to_owned());
                    }
                    MessagePartTypes::CENTER => {
                        return Err("Last part is CENTER, but should be END".to_owned());
                    }
                    MessagePartTypes::END => {}
                    part_type => {
                        return Ok(DeserializedMessageCheck {
                            kind: DeserializedMessageCheckKind::InvalidEndType(part_type),
                        });
                    }
                }

                let diff = first.id().wrapping_add(vec_ref.len() as u8) - 1;

                if diff != last.id() {
                    return Err(format!(
                        "The size of the message parts ({:?}) did not match, target diff: {:?}, last id: {:?}",
                        vec_ref.len(), diff, last.id()
                    ));
                }

                return Ok(DeserializedMessageCheck {
                    kind: DeserializedMessageCheckKind::EndConfirmed,
                });
            }
            MessagePartTypes::CENTER => {
                return Err("First part is CENTER, but should be START or SINGLE".to_owned());
            }
            MessagePartTypes::END => {
                return Err("First part is END, but should be SINGLE or START".to_owned());
            }
            part_type => {
                return Ok(DeserializedMessageCheck {
                    kind: DeserializedMessageCheckKind::InvalidStartType(part_type),
                });
            }
        }
    }
}

pub struct DeserializedMessage {
    packets: Vec<DeserializedPacket>,
}

impl DeserializedMessage {
    pub fn deserialize(
        packet_registry: &PacketRegistry,
        check: DeserializedMessageCheck,
        mut vec: OrderedRotatableU8Vec<MessagePart>,
    ) -> Result<Self, String> {
        let vec_mut = vec.vec_mut();

        match check.kind {
            DeserializedMessageCheckKind::Single => {
                let last = &vec_mut[vec_mut.len() - 1];
                return Ok(DeserializedMessage {
                    packets: DeserializedPacket::deserialize_list(
                        last.content(),
                        &packet_registry,
                    )?,
                });
            }

            DeserializedMessageCheckKind::EndConfirmed => {
                let total_capacity: usize = vec_mut
                    .iter()
                    .map(|part| part.bytes.len().saturating_sub(2))
                    .sum();
                let mut unified_messages: Vec<u8> = Vec::with_capacity(total_capacity);

                for part in vec.take_vec() {
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
                return Err(format!("Invalid start type {:?}", part_type));
            }
            DeserializedMessageCheckKind::InvalidEndType(part_type) => {
                return Err(format!("Invalid end type {:?}", part_type));
            }
        }
    }
}
