//! Provides a trait that can be implemented to apply a filter to a table or bucket.

pub trait Filter<TVal>: FilterClone<TVal> + Send + Sync {
    fn filter<'a>(value: &'a TVal, other_vals: impl Iterator<Item = &'a TVal>) -> bool
    where
        Self: Sized;
}

/// Allow the trait objects to be cloneable.
pub trait FilterClone<TVal> {
    fn clone_box(&self) -> Box<dyn Filter<TVal>>;
}

impl<T, TVal> FilterClone<TVal> for T
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
