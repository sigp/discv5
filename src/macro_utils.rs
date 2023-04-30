/// Implements From for an enum from some type. Takes the type to nest, the enum and the variant.
#[macro_export]
macro_rules! impl_from_variant_wrap {
    ($from_type: ty, $to_type: ty, $variant: path) => {
        impl From<$from_type> for $to_type {
            fn from(t: $from_type) -> Self {
                $variant(t)
            }
        }
    };
}
