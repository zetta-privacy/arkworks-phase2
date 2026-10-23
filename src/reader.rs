use std::{io::Read, ops::Div};

use ark_ec::{
    bn::{Bn, BnConfig},
    pairing::Pairing,
};
use ark_ff::{BigInteger, Fp2, PrimeField};

use crate::error::Error;

fn montgomery_r<F: PrimeField>() -> F {
    F::from_bigint(F::BigInt::from(2u64))
        .unwrap()
        .pow([(64 * F::BigInt::NUM_LIMBS) as u64])
}

pub trait PairingReader: Pairing {
    fn read_ptau_g1<R: Read>(reader: &mut R) -> Result<Self::G1Affine, Error>;
    fn read_ptau_g2<R: Read>(reader: &mut R) -> Result<Self::G2Affine, Error>;

    fn read_radix_g1<R: Read>(reader: &mut R) -> Result<Self::G1Affine, Error>;
    fn read_radix_g2<R: Read>(reader: &mut R) -> Result<Self::G2Affine, Error>;
}

impl<T: BnConfig> PairingReader for Bn<T> {
    fn read_ptau_g1<R: Read>(reader: &mut R) -> Result<Self::G1Affine, Error> {
        let r = montgomery_r::<Self::BaseField>();
        let len = <Self::BaseField as PrimeField>::BigInt::NUM_LIMBS * 8;
        let mut b = vec![0; len * 2];
        reader.read_exact(&mut b)?;

        let x = Self::BaseField::from_le_bytes_mod_order(&b[..len]).div(r);
        let y = Self::BaseField::from_le_bytes_mod_order(&b[len..]).div(r);

        let g1 = Self::G1Affine::new(x, y);
        assert!(g1.is_on_curve(), "G1 must be on curve");
        Ok(g1)
    }

    fn read_ptau_g2<R: Read>(reader: &mut R) -> Result<Self::G2Affine, Error> {
        let r = montgomery_r::<Self::BaseField>();
        let len = <Self::BaseField as PrimeField>::BigInt::NUM_LIMBS * 8;
        let mut b = vec![0; len * 4];
        reader.read_exact(&mut b)?;

        let x0 = Self::BaseField::from_le_bytes_mod_order(&b[..len]).div(r);
        let x1 = Self::BaseField::from_le_bytes_mod_order(&b[len..(len * 2)]).div(r);
        let x = Fp2::<T::Fp2Config>::new(x0, x1);
        let y0 = Self::BaseField::from_le_bytes_mod_order(&b[(len * 2)..(len * 3)]).div(r);
        let y1 = Self::BaseField::from_le_bytes_mod_order(&b[(len * 3)..]).div(r);
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
