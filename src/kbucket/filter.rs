pub trait Filter<TNodeId, TVal>: Send + Sync {
    fn filter<'a>(value: &'a TVal, other_vals: impl Iterator<Item = &'a TVal>) -> bool
    where
        Self: Sized;
}
