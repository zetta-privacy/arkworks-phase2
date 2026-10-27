use std::io::Read;

use ark_ec::{
    bn::{Bn, BnConfig},
    pairing::Pairing,
    AffineRepr,
};
use ark_ff::{BigInteger, Field, Fp2, PrimeField};

use crate::error::Error;

pub fn montgomery_r<F: PrimeField>() -> F {
    F::from_bigint(F::BigInt::from(2u64))
        .unwrap()
        .pow([(64 * F::BigInt::NUM_LIMBS) as u64])
}

pub trait PairingReader: Pairing {
    fn parse_ptau_g1(bytes: &[u8], r_inv: &Self::BaseField) -> Result<Self::G1Affine, Error>;
    fn parse_ptau_g2(bytes: &[u8], r_inv: &Self::BaseField) -> Result<Self::G2Affine, Error>;

    fn read_ptau_g1<R: Read>(
        reader: &mut R,
        r_inv: &Self::BaseField,
    ) -> Result<Self::G1Affine, Error>;
    fn read_ptau_g2<R: Read>(
        reader: &mut R,
        r_inv: &Self::BaseField,
    ) -> Result<Self::G2Affine, Error>;

    fn read_radix_g1<R: Read>(reader: &mut R) -> Result<Self::G1Affine, Error>;
    fn read_radix_g2<R: Read>(reader: &mut R) -> Result<Self::G2Affine, Error>;
}

impl<T: BnConfig> PairingReader for Bn<T> {
    fn parse_ptau_g1(bytes: &[u8], r_inv: &Self::BaseField) -> Result<Self::G1Affine, Error> {
        let len = <Self::BaseField as PrimeField>::BigInt::NUM_LIMBS * 8;
        let x = Self::BaseField::from_le_bytes_mod_order(&bytes[..len]) * *r_inv;
        let y = Self::BaseField::from_le_bytes_mod_order(&bytes[len..]) * *r_inv;
        let g1 = Self::G1Affine::new(x, y);
        assert!(g1.is_on_curve(), "G1 must be on curve");
        Ok(g1)
    }

    fn parse_ptau_g2(bytes: &[u8], r_inv: &Self::BaseField) -> Result<Self::G2Affine, Error> {
        let len = <Self::BaseField as PrimeField>::BigInt::NUM_LIMBS * 8;
        let x0 = Self::BaseField::from_le_bytes_mod_order(&bytes[..len]) * *r_inv;
        let x1 = Self::BaseField::from_le_bytes_mod_order(&bytes[len..(len * 2)]) * *r_inv;
        let x = Fp2::<T::Fp2Config>::new(x0, x1);
        let y0 = Self::BaseField::from_le_bytes_mod_order(&bytes[(len * 2)..(len * 3)]) * *r_inv;
        let y1 = Self::BaseField::from_le_bytes_mod_order(&bytes[(len * 3)..]) * *r_inv;
        let y = Fp2::<T::Fp2Config>::new(y0, y1);
        let g2 = Self::G2Affine::new(x, y);
        assert!(g2.is_on_curve(), "G2 must be on curve");
        Ok(g2)
    }

    fn read_ptau_g1<R: Read>(
        reader: &mut R,
        r_inv: &Self::BaseField,
    ) -> Result<Self::G1Affine, Error> {
        let len = <Self::BaseField as PrimeField>::BigInt::NUM_LIMBS * 8;
        let mut b = vec![0; len * 2];
        reader.read_exact(&mut b)?;

        let x = Self::BaseField::from_le_bytes_mod_order(&b[..len]) * *r_inv;
        let y = Self::BaseField::from_le_bytes_mod_order(&b[len..]) * *r_inv;

        let g1 = Self::G1Affine::new(x, y);
        assert!(g1.is_on_curve(), "G1 must be on curve");
        Ok(g1)
    }

    fn read_ptau_g2<R: Read>(
        reader: &mut R,
        r_inv: &Self::BaseField,
    ) -> Result<Self::G2Affine, Error> {
        let len = <Self::BaseField as PrimeField>::BigInt::NUM_LIMBS * 8;
        let mut b = vec![0; len * 4];
        reader.read_exact(&mut b)?;

        let x0 = Self::BaseField::from_le_bytes_mod_order(&b[..len]) * *r_inv;
        let x1 = Self::BaseField::from_le_bytes_mod_order(&b[len..(len * 2)]) * *r_inv;
        let x = Fp2::<T::Fp2Config>::new(x0, x1);
        let y0 = Self::BaseField::from_le_bytes_mod_order(&b[(len * 2)..(len * 3)]) * *r_inv;
        let y1 = Self::BaseField::from_le_bytes_mod_order(&b[(len * 3)..]) * *r_inv;
        let y = Fp2::<T::Fp2Config>::new(y0, y1);
        let g2 = Self::G2Affine::new(x, y);

        assert!(g2.is_on_curve(), "G2 must be on curve");
        Ok(g2)
    }

    fn read_radix_g1<R: Read>(reader: &mut R) -> Result<Self::G1Affine, Error> {
        let len = <Self::BaseField as PrimeField>::BigInt::NUM_LIMBS * 8;
        let x = {
            let mut b = vec![0; len];
            reader.read_exact(&mut b)?;
            b[0] &= 0x3f;
            b.reverse();
            Self::BaseField::from_le_bytes_mod_order(&b[..])
        };
        let y = {
            let mut b = vec![0; len];
            reader.read_exact(&mut b)?;
            b.reverse();
            Self::BaseField::from_le_bytes_mod_order(&b[..])
        };
        let g1 = Self::G1Affine::new(x, y);
        assert!(g1.is_on_curve(), "G1 must be on curve");
        Ok(g1)
    }

    fn read_radix_g2<R: Read>(reader: &mut R) -> Result<Self::G2Affine, Error> {
        let len = <Self::BaseField as PrimeField>::BigInt::NUM_LIMBS * 8;
        let x1 = {
            let mut b = vec![0; len];
            reader.read_exact(&mut b)?;
            b.reverse();
            Self::BaseField::from_le_bytes_mod_order(&b[..])
        };
        let x0 = {
            let mut b = vec![0; len];
            reader.read_exact(&mut b)?;
            b[0] &= 0x3f;
            b.reverse();
            Self::BaseField::from_le_bytes_mod_order(&b[..])
        };
        let x = Fp2::<T::Fp2Config>::new(x0, x1);
        let y1 = {
            let mut b = vec![0; len];
            reader.read_exact(&mut b)?;
            b.reverse();
            Self::BaseField::from_le_bytes_mod_order(&b[..])
        };
        let y0 = {
            let mut b = vec![0; len];
            reader.read_exact(&mut b)?;
            b.reverse();
            Self::BaseField::from_le_bytes_mod_order(&b[..])
        };
        let y = Fp2::<T::Fp2Config>::new(y0, y1);
        let g2 = Self::G2Affine::new(x, y);
        assert!(g2.is_on_curve(), "G2 must be on curve");
        Ok(g2)
    }
}

pub fn write_ptau_g1<E: Pairing>(point: &E::G1Affine, r: &E::BaseField) -> Vec<u8>
where
    E::G1Affine: AffineRepr<BaseField = E::BaseField>,
{
    let (x, y) = point.xy().unwrap();
    let mut out = Vec::with_capacity(64);
    out.extend_from_slice(&montgomery_coeff(x, r));
    out.extend_from_slice(&montgomery_coeff(y, r));
    out
}

pub fn write_ptau_g2<E: Pairing>(point: &E::G2Affine, r: &E::BaseField) -> Vec<u8>
where
    <E::G2Affine as AffineRepr>::BaseField: Field<BasePrimeField = E::BaseField>,
{
    let (x, y) = point.xy().unwrap();
    let mut out = Vec::with_capacity(128);
    for c in x
        .to_base_prime_field_elements()
        .chain(y.to_base_prime_field_elements())
    {
        out.extend_from_slice(&montgomery_coeff(c, r));
    }
    out
}

fn montgomery_coeff<F: PrimeField>(c: F, r: &F) -> Vec<u8> {
    (c * *r).into_bigint().to_bytes_le()
}

pub fn montgomery_r_inv<F: PrimeField>() -> F {
    montgomery_r::<F>().inverse().unwrap()
}
