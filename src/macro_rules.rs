/// Implements the From trait for an enum from some type. Nests a type in a variant with a single
/// value. Takes any generics, the type to nest, the enum and the variant.
#[macro_export]
macro_rules! impl_from_variant_wrap {
    ($(<$($generic: ident$(: $trait: ident$(+ $traits: ident)*)*,)+>)*, $from_type: ty, $to_enum: ty, $to_variant: path) => {
        impl$(<$($generic $(: $trait $(+ $traits)*)*,)+>)* From<$from_type> for $to_enum {
            fn from(t: $from_type) -> Self {
                $to_variant(t)
            }
        }
    };
}

/// Implements the From trait for some type from an enum. Extracts a type nested in a variant with
/// a single value. Takes any generics, the enum, the type nested in the variant and the variant.
#[macro_export]
macro_rules! impl_from_variant_unwrap {
    ($(<$($generic: ident$(: $trait: ident$(+ $traits: ident)*)*,)+>)*, $from_enum: ty, $to_type: ty, $from_variant: path) => {
        impl$(<$($generic $(: $trait $(+ $traits)*)*,)+>)* From<$from_enum> for $to_type {
            fn from(e: $from_enum) -> Self {
                if let $from_variant(v) = e {
                    return v;
                }
                panic!("Bad impl of From")
            }
        }
    };
}

/// Implements the From trait for some type from a (1-)tuple struct. Extracts a type nested in a
/// 1-tuple tuple struct. Takes any generics, the tuple struct type and the type nested in the
/// tuple struct.
#[macro_export]
macro_rules! impl_from_tuple_struct_unwrap {
    ($(<$($generic: ident$(: $trait: ident$(+ $traits: ident)*)*,)+>)*, $from_tuple_struct: ty, $to_type: ty) => {
        impl$(<$($generic $(: $trait $(+ $traits)*)*,)+>)* From<$from_tuple_struct> for $to_type {
            fn from(s: $from_tuple_struct) -> Self {
                s.0
            }
        }
    };
}
