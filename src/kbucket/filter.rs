//! Provides a trait that can be implemented to apply a filter to a table or bucket.

use crate::{discv5::EnrExtension, Enr};
pub trait Filter<TVal: Eq>: FilterClone<TVal> + Send + Sync {
    fn filter(
        &self,
        value_to_be_inserted: &TVal,
        other_vals: &mut dyn Iterator<Item = &TVal>,
    ) -> bool;
}

/// Allow the trait objects to be cloneable.
pub trait FilterClone<TVal: Eq> {
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

impl<TVal: Eq> Clone for Box<dyn Filter<TVal>> {
    fn clone(&self) -> Box<dyn Filter<TVal>> {
        self.clone_box()
    }
}

// Implementation of an IP filter for buckets and for tables

/// Number of permitted nodes in the same /24 subnet per table.
const MAX_NODES_PER_SUBNET_TABLE: usize = 10;
/// The number of nodes permitted in the same /24 subnet per bucket.
const MAX_NODES_PER_SUBNET_BUCKET: usize = 2;
/// Number of permitted nodes behind a NAT per subnet per bucket.
const MAX_NODES_BEHIND_NAT_PER_SUBNET_BUCKET: usize = 2;

#[derive(Clone)]
pub struct IpTableFilter;

impl Filter<Enr> for IpTableFilter {
    fn filter(
        &self,
        value_to_be_inserted: &Enr,
        other_vals: &mut dyn Iterator<Item = &Enr>,
    ) -> bool {
        ip_filter(value_to_be_inserted, other_vals, MAX_NODES_PER_SUBNET_TABLE)
    }
}

#[derive(Clone)]
pub struct IpBucketFilter;

impl Filter<Enr> for IpBucketFilter {
    fn filter(
        &self,
        value_to_be_inserted: &Enr,
        other_vals: &mut dyn Iterator<Item = &Enr>,
    ) -> bool {
        ip_filter(
            value_to_be_inserted,
            other_vals,
            MAX_NODES_PER_SUBNET_BUCKET,
        )
    }
}

fn ip_filter(
    value_to_be_inserted: &Enr,
    other_vals: &mut dyn Iterator<Item = &Enr>,
    limit: usize,
) -> bool {
    if let Some(ip) = value_to_be_inserted.ip4() {
        let mut count = 0;
        for enr in other_vals {
            // Ignore duplicates
            if enr == value_to_be_inserted {
                continue;
            }
            // Count the same /24 subnet
            if let Some(other_ip) = enr.ip4() {
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

#[derive(Clone)]
pub struct SymmetricNatBucketFilter;

impl Filter<Enr> for SymmetricNatBucketFilter {
    fn filter(
        &self,
        value_to_be_inserted: &Enr,
        other_vals: &mut dyn Iterator<Item = &Enr>,
    ) -> bool {
        symmetric_nat_filter(
            value_to_be_inserted,
            other_vals,
            MAX_NODES_BEHIND_NAT_PER_SUBNET_BUCKET,
        )
    }
}

fn symmetric_nat_filter(
    value_to_be_inserted: &Enr,
    other_vals: &mut dyn Iterator<Item = &Enr>,
    limit: usize,
) -> bool {
    let mut count = 0;
    for enr in other_vals {
        // Ignore duplicates
        if enr == value_to_be_inserted {
            continue;
        }
        // Count nodes which are behind a symmetric nat
        if enr.udp4().is_none() && enr.nat4().is_some()
            || enr.udp6().is_none() && enr.nat6().is_some()
        {
            count += 1;
        }
        if count >= limit {
            return false;
        }
    }
    true // No nat field, so no restrictions
}

#[derive(Clone)]
pub struct IpAndSymmetricNatBucketFilter;

impl Filter<Enr> for IpAndSymmetricNatBucketFilter {
    fn filter(
        &self,
        value_to_be_inserted: &Enr,
        other_vals: &mut dyn Iterator<Item = &Enr>,
    ) -> bool {
        ip_filter(
            value_to_be_inserted,
            other_vals,
            MAX_NODES_PER_SUBNET_BUCKET,
        ) && symmetric_nat_filter(
            value_to_be_inserted,
            other_vals,
            MAX_NODES_BEHIND_NAT_PER_SUBNET_BUCKET,
        )
    }
}
