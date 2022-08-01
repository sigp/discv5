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
use std::{fmt, hash::Hash};
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

/// The 32-bytes that are sent in the body of a topic request are interpreted
/// as a hash by the agreed upon hash algorithm in the discv5 network (defaults
/// to Sha256).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TopicHash {
    /// The topic hash. Stored as a fixed length byte array.
    hash: [u8; 32],
}

impl TopicHash {
    /// Returns a topic hash wrapping the given 32 bytes.
    pub fn from_raw(hash: [u8; 32]) -> TopicHash {
        TopicHash { hash }
    }

    /// Returns the raw 32 bytes inside a topic hash.
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

impl fmt::Display for TopicHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", encode(self.hash))
    }
}

/// A topic, as in sigpi/rust-libp2p/protocols/gossipsub.
#[derive(Debug, Clone)]
pub struct Topic<H: Hasher> {
    /// The topic string passed to the topic upon instantiation.
    topic: String,
    /// The configured [`Hasher`] is stored within the topic.
    phantom_data: std::marker::PhantomData<H>,
}

impl<H: Hasher> From<Topic<H>> for TopicHash {
    fn from(topic: Topic<H>) -> TopicHash {
        topic.hash()
    }
}

impl<H: Hasher> Topic<H> {
    /// Returns a new topic.
    pub fn new(topic: impl Into<String>) -> Self {
        Topic {
            topic: topic.into(),
            phantom_data: std::marker::PhantomData,
        }
    }

    /// Returns a hash of the topic using the [`Hasher`] configured for the topic.
    pub fn hash(&self) -> TopicHash {
        H::hash(self.topic.clone())
    }
    
    /// Returns the string passed to the topic upon instantiation.
    pub fn topic(&self) -> String {
        self.topic.clone()
    }
}

impl<H: Hasher> PartialEq for Topic<H> {
    /// Each hash algortihm used to publish a hashed topic (as XOR metric key) is in
    /// discv5 seen as its own [`Topic<H>`] upon comparison. That means a topic string
    /// can be published/registered more than once using different [`Hasher`]s.
    fn eq(&self, other: &Topic<H>) -> bool {
        self.hash() == other.hash()
    }
}

impl<H: Hasher> Eq for Topic<H> {}

impl<H: Hasher> fmt::Display for Topic<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.topic)
    }
}
