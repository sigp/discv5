type Topic = [u8; 32];

// Temporary, some hash function will probably be used here instead of padding
pub fn topic_hash(topic: Vec<u8>) -> Result<Topic, String> {
    if topic.len() > 32 {
        return Err("Topic is greater than 32 bytes".into());
    }
    let mut topic_hash = [0u8; 32];
    topic_hash[32 - topic.len()..].copy_from_slice(&topic);
    Ok(topic_hash)
}
