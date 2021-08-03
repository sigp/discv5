pub mod kbucket;
pub type Enr = enr::Enr<enr::CombinedKey>;
// re-export the ENR crate
pub use enr;
