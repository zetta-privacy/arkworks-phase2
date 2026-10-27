use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use ark_bn254::Bn254;
use ark_serialize::CanonicalDeserialize;
use arkworks_phase2::accumulator::Accumulator;
use arkworks_phase2::key::PartialKey;
use arkworks_phase2::keypair::PublicKey;
use arkworks_phase2::transcript::Transcript;
use arkworks_phase2::utils::serialize_uncompressed;
use clap::{Parser, Subcommand, ValueEnum};
use rand::rngs::OsRng;

const PHASE2_DIR: &str = "data";

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init {
        /// power of two (e.g. 24 = 2^24 constraints)
        #[arg(long)]
        power: usize,
        #[arg(long)]
        ptau: PathBuf,
    },
    Contribute {
        #[arg(long)]
        circuit: Circuit,
    },
    Finalize {
        #[arg(long)]
        circuit: Circuit,
    },
    /// Generate a single-party dev ptau (untrusted — dev only).
    GenPtau {
        /// power of two (e.g. 24 = 2^24 constraints)
        #[arg(long)]
        power: usize,
        #[arg(long)]
        output: PathBuf,
    },
    /// Download a PSE "prepared phase 2" ptau.
    DownloadPtau {
        /// power of two (1..=28)
        #[arg(long)]
        power: usize,
        #[arg(long)]
        output: PathBuf,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum Circuit {
    Root,
    Withdraw,
}

impl Circuit {
    fn name(self) -> &'static str {
        match self {
            Circuit::Root => "root",
            Circuit::Withdraw => "withdraw",
        }
    }
}

fn dir(circuit: Circuit) -> PathBuf {
    Path::new(PHASE2_DIR).join(circuit.name())
}

fn init(power: usize, ptau: &Path) -> Result<(), Box<dyn Error>> {
    let accum = Accumulator::<Bn254>::from_ptau_file(ptau)?;
    let prepared = accum.prepare_with_size(1 << power)?; // FFTs once

    for circuit in [Circuit::Root] {
        let transcript = match circuit {
            Circuit::Root => {
                Transcript::new_from_prepared_accumulator(&prepared, zkp::root_decider_circuit()?)?
            }
            // Circuit::Withdraw => Transcript::new_from_prepared_accumulator(
            //     &prepared,
            //     zkp::withdraw_decider_circuit()?,
            // )?,
            _ => continue,
        };
        let d = dir(circuit);
        fs::create_dir_all(&d)?;

        // coordinator keeps the full transcript (static a/b queries live here)
        fs::write(
            d.join("transcript.bin"),
            serialize_uncompressed(&transcript)?,
        )?;
        // participants only touch the PartialKey (delta + h_query + l_query)
        fs::write(
            d.join("current_key.bin"),
            serialize_uncompressed(&transcript.initial_key)?,
        )?;
        // contribution chain
        let empty: Vec<PublicKey<Bn254>> = vec![];
        fs::write(d.join("contributions.bin"), serialize_uncompressed(&empty)?)?;
    }

    Ok(())
}

fn contribute(circuit: Circuit) -> Result<(), Box<dyn Error>> {
    let d = dir(circuit);

    let mut current: PartialKey<Bn254> = {
        let bytes = fs::read(d.join("current_key.bin"))?;
        PartialKey::deserialize_uncompressed(&bytes[..])?
    };
    let mut contributions: Vec<PublicKey<Bn254>> = {
        let bytes = fs::read(d.join("contributions.bin"))?;
        Vec::deserialize_uncompressed(&bytes[..])?
    };

    let proof = current.contribute_rng(&mut OsRng)?;
    contributions.push(PublicKey {
        delta_g2: current.delta_g2,
        proof,
    });

    fs::write(d.join("current_key.bin"), serialize_uncompressed(&current)?)?;
    fs::write(
        d.join("contributions.bin"),
        serialize_uncompressed(&contributions)?,
    )?;

    Ok(())
}

fn finalize(circuit: Circuit) -> Result<(), Box<dyn Error>> {
    let d = dir(circuit);

    let mut transcript: Transcript<Bn254> = {
        let bytes = fs::read(d.join("transcript.bin"))?;
        Transcript::deserialize_uncompressed(&bytes[..])?
    };
    let current: PartialKey<Bn254> = {
        let bytes = fs::read(d.join("current_key.bin"))?;
        PartialKey::deserialize_uncompressed(&bytes[..])?
    };
    let contributions: Vec<PublicKey<Bn254>> = {
        let bytes = fs::read(d.join("contributions.bin"))?;
        Vec::deserialize_uncompressed(&bytes[..])?
    };

    // static parts (a/b queries) come from the transcript; dynamic parts from `current`
    transcript.key.key.delta_g1 = current.delta_g1;
    transcript.key.key.vk.delta_g2 = current.delta_g2;
    transcript.key.key.h_query = current.h_query.clone();
    transcript.key.key.l_query = current.l_query.clone();
    transcript.contributions = contributions;

    transcript.verify()?;

    fs::write(
        d.join("final_transcript.bin"),
        serialize_uncompressed(&transcript)?,
    )?;
    Ok(())
}

fn gen_dev_ptau(power: usize, output: &Path) -> Result<(), Box<dyn Error>> {
    let mut accum = Accumulator::<Bn254>::empty_from_degree(power)?;
    accum.contribute(&mut OsRng);
    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }
    accum.write_ptau_file(output)?;
    println!("wrote dev ptau (power {power}) to {}", output.display());
    Ok(())
}

fn download_pse_ptau(power: usize, output: &Path) -> Result<(), Box<dyn Error>> {
    let filename = if power == 28 {
        "ppot_0080_final.ptau".to_string()
    } else {
        format!("ppot_0080_{power:02}.ptau")
    };
    let url = format!(
        "https://pse-trusted-setup-ppot.s3.eu-central-1.amazonaws.com/pot28_0080/{filename}"
    );

    if let Some(parent) = output.parent() {
        fs::create_dir_all(parent)?;
    }

    println!("downloading {url}\n-> {}", output.display());
    let status = std::process::Command::new("curl")
        .args(["-L", "-C", "-", "--fail", "-o"])
        .arg(output)
        .arg(&url)
        .status()?;

    if !status.success() {
        return Err(format!("curl exited with {status}").into());
    }
    println!("done");
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    match Cli::parse().command {
        Command::Init { power, ptau } => init(power, &ptau),
        Command::Contribute { circuit } => contribute(circuit),
        Command::Finalize { circuit } => finalize(circuit),
        Command::GenPtau { power, output } => gen_dev_ptau(power, &output),
        Command::DownloadPtau { power, output } => download_pse_ptau(power, &output),
    }
}
