//! Implements the static ecdh algorithm required by discv5 in terms of the `k256` library.
use k256::elliptic_curve::sec1::FromEncodedPoint;
use k256::{ecdsa::SigningKey, ecdsa::VerifyKey};

pub fn ecdh_x(public_key: &VerifyKey, secret_key: &SigningKey) -> Vec<u8> {
    k256::elliptic_curve::ecdh::PublicKey::from(
        (k256::ProjectivePoint::from(
            k256::elliptic_curve::AffinePoint::<k256::Secp256k1>::from_encoded_point(
                &k256::elliptic_curve::ecdh::PublicKey::from_bytes(public_key.to_bytes().as_ref())
                    .unwrap(),
            )
            .unwrap(),
        ) * k256::SecretKey::from_bytes(secret_key.to_bytes())
            .unwrap()
            .secret_scalar())
        .to_affine(),
    )
    .as_bytes()
    .to_vec()
}
