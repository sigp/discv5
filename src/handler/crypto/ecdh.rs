//! Implements the static ecdh algorithm required by discv5 in terms of the `k256` library.
use enr::k256::elliptic_curve::sec1::ToSec1Point;

use super::k256::{
    self,
    ecdsa::{SigningKey, VerifyingKey},
};

pub fn ecdh(public_key: &VerifyingKey, secret_key: &SigningKey) -> Vec<u8> {
    let public_point = k256::ProjectivePoint::from(public_key.as_affine());
    let shared_point = (public_point * **secret_key.as_nonzero_scalar()).to_affine();
    shared_point.to_sec1_point(true).as_bytes().to_vec()
}
