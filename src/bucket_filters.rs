//! This houses a collection of bucket filters used to limit nodes entering buckets.


/// Takes an `ENR` to insert and a list of other `ENR`s to compare against.
/// Returns `true` if `ENR` can be inserted and `false` otherwise.
/// `enr` can be inserted if the count of enrs in `others` in the same /24 subnet as `ENR`
/// is less than `limit`.
pub fn ip_limiter(enr: &Enr, others: &[&Enr], limit: usize) -> bool {
    let mut allowed = true;
    if let Some(ip) = enr.ip() {
        let count = others.iter().flat_map(|e| e.ip()).fold(0, |acc, x| {
            if x.octets()[0..3] == ip.octets()[0..3] {
                acc + 1
            } else {
                acc
            }
        });
        if count >= limit {
            allowed = false;
        }
    };
    allowed
}
