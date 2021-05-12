//! Provides a trait that can be implemented to apply a filter to a table or bucket.

use crate::Enr;

pub trait Filter<TVal: Eq>: FilterClone<TVal> + Send + Sync {
    fn filter<'a>(
        value_to_be_inserted: &'a TVal,
        other_vals: impl Iterator<Item = &'a TVal>,
    ) -> bool
    where
        Self: Sized;
}

/// Allow the trait objects to be cloneable.
pub trait FilterClone<TVal> {
    fn clone_box(&self) -> Box<dyn Filter<TVal>>;
}

impl<T, TVal: Eq> FilterClone<TVal> for T
where
    T: 'static + Filter<TVal> + Clone,
{
    fn clone_box(&self) -> Box<dyn Filter<TVal>> {
        Box::new(self.clone())
    }
}

impl<TVal> Clone for Box<dyn Filter<TVal>> {
    fn clone(&self) -> Box<dyn Filter<TVal>> {
        self.clone_box()
    }
}

// Implementation of an IP filter for buckets and for tables

/// Number of permitted nodes in the same /24 subnet per table.
const MAX_NODES_PER_SUBNET_TABLE: usize = 10;
/// The number of nodes permitted in the same /24 subnet per bucket.
const MAX_NODES_PER_SUBNET_BUCKET: usize = 2;

#[derive(Clone)]
pub struct IpTableFilter;

impl Filter<Enr> for IpTableFilter {
    fn filter<'a>(
        value_to_be_inserted: &'a Enr,
        other_vals: impl Iterator<Item = &'a Enr>,
    ) -> bool {
        ip_filter(value_to_be_inserted, other_vals, MAX_NODES_PER_SUBNET_TABLE)
    }
}

#[derive(Clone)]
pub struct IpBucketFilter;

impl Filter<Enr> for IpBucketFilter {
    fn filter<'a>(
        value_to_be_inserted: &'a Enr,
        other_vals: impl Iterator<Item = &'a Enr>,
    ) -> bool {
        ip_filter(
            value_to_be_inserted,
            other_vals,
            MAX_NODES_PER_SUBNET_BUCKET,
        )
    }
}

fn ip_filter<'a>(
    value_to_be_inserted: &'a Enr,
    other_vals: impl Iterator<Item = &'a Enr>,
    limit: usize,
) -> bool {
    if let Some(ip) = value_to_be_inserted.ip() {
        let mut count = 0;
        for enr in other_vals {
            // Ignore duplicates
            if enr == value_to_be_inserted {
                continue;
            }

            // Count the same /24 subnet
            if let Some(other_ip) = enr.ip() {
                if other_ip.octets()[0..3] == ip.octets()[0..3] {
                    count += 1;
                }
            }
            if count >= limit {
                return false;
            }
        }
    }
    // No IP, so no restrictions
    true
}
