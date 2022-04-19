// Copyright 2020 Sigma Prime Pty Ltd.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.

use base64::encode;
use rlp::{DecoderError, Rlp, RlpStream};
use sha2::{Digest, Sha256};
use std::{cmp::Ordering, fmt, hash::Hash};
use tracing::debug;

//pub type IdentTopic = Topic<IdentityHash>;
pub type Sha256Topic = Topic<Sha256Hash>;

/// A generic trait that can be extended for various hashing types for a topic.
pub trait Hasher {
    /// The function that takes a topic string and creates a topic hash.
    fn hash(topic_string: String) -> TopicHash;
}

/// A type for representing topics who use the identity hash.
/*#[derive(Debug, Clone)]
pub struct IdentityHash {}
impl Hasher for IdentityHash {
    /// Creates a [`TopicHash`] as a raw string.
    fn hash(topic_string: String) -> TopicHash {
        TopicHash { hash: topic_string.as_bytes() }
    }
}*/

#[derive(Debug, Clone)]
pub struct Sha256Hash {}
impl Hasher for Sha256Hash {
    /// Creates a [`TopicHash`] by SHA256 hashing the topic then base64 encoding the
    /// hash.
    fn hash(topic_string: String) -> TopicHash {
        let sha256 = Sha256::digest(topic_string.as_bytes());
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&sha256);
        TopicHash { hash }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TopicHash {
    /// The topic hash. Stored as a string to align with the protobuf API.
    hash: [u8; 32],
}

// Topic Hash decoded into bytes needs to have length 32 bytes to encode it into a
// NodeId, which is necessary to make use of the XOR distance look-up of a topic. It
// makes sense to use a hashing algorithm which produces 32 bytes since the hash of
// any given topic string can then be reproduced by any client when making a topic
// query or publishing the same topic in proximity to others of its kind.
impl TopicHash {
    pub fn from_raw(hash: [u8; 32]) -> TopicHash {
        TopicHash { hash }
    }

    pub fn as_bytes(&self) -> [u8; 32] {
        self.hash
    }
}

impl rlp::Encodable for TopicHash {
    fn rlp_append(&self, s: &mut RlpStream) {
        s.append(&self.hash.to_vec());
    }
}

impl rlp::Decodable for TopicHash {
    fn decode(rlp: &Rlp<'_>) -> Result<Self, DecoderError> {
        let topic = {
            let topic_bytes = rlp.data()?;
            if topic_bytes.len() > 32 {
                debug!("Topic greater than 32 bytes");
                return Err(DecoderError::RlpIsTooBig);
            }
            let mut topic = [0u8; 32];
            topic[32 - topic_bytes.len()..].copy_from_slice(topic_bytes);
            topic
        };
        Ok(TopicHash::from_raw(topic))
    }
}

/// A gossipsub topic.
#[derive(Debug, Clone)]
pub struct Topic<H: Hasher> {
    topic: String,
    phantom_data: std::marker::PhantomData<H>,
}

impl<H: Hasher> From<Topic<H>> for TopicHash {
    fn from(topic: Topic<H>) -> TopicHash {
        topic.hash()
    }
}

impl<H: Hasher> Topic<H> {
    pub fn new(topic: impl Into<String>) -> Self {
        Topic {
            topic: topic.into(),
            phantom_data: std::marker::PhantomData,
        }
    }

    pub fn hash(&self) -> TopicHash {
        H::hash(self.topic.clone())
    }

    pub fn topic(&self) -> String {
        self.topic.clone()
    }
}

// Each hash algortihm chosen to publish a topic with (as XOR
// metric key) is its own Topic
impl<H: Hasher> PartialEq for Topic<H> {
    fn eq(&self, other: &Topic<H>) -> bool {
        self.hash() == other.hash()
    }
}

impl<H: Hasher> Eq for Topic<H> {}

impl<H: Hasher> Hash for Topic<H> {
    fn hash<T: std::hash::Hasher>(&self, _state: &mut T) {
        self.hash();
    }
}

// When sorted topics should group based on the topic string
impl<H: Hasher> PartialOrd for Topic<H> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.topic.cmp(&other.topic))
    }
}

impl<H: Hasher> Ord for Topic<H> {
    fn cmp(&self, other: &Self) -> Ordering {
        self.topic.cmp(&other.topic)
    }
}

impl<H: Hasher> fmt::Display for Topic<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.topic)
    }
}

impl fmt::Display for TopicHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", encode(self.hash))
    }
}
