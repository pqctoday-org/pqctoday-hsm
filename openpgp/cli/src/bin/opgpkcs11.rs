use std::path::PathBuf;
use std::str::FromStr;

use anyhow::Result;
use clap::Parser;
use cryptoki::object::{Attribute, AttributeType};
use openpgp_pkcs11_sequoia::Op11;
use openpgp_pkcs11_sequoia::PgpKeyType;
use sequoia_openpgp::cert::prelude::ValidErasedKeyAmalgamation;
use sequoia_openpgp::packet::key::SecretParts;
use sequoia_openpgp::parse::Parse;
use sequoia_openpgp::policy::StandardPolicy;
use sequoia_openpgp::{Cert, Fingerprint};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[clap(subcommand)]
    pub cmd: Command,

    #[clap(long, default_value = "/usr/lib64/libykcs11.so")]
    pub module: String,
}

#[derive(Parser, Debug)]
pub enum Command {
    /// List serials of PKCS #11 devices
    List {},

    /// Show OpenPGP key metadata for an Object ID on the card
    Show {
        /// PKCS #11 device serial
        #[clap(long)]
        serial: String,

        /// Object ID
        #[clap(long)]
        id: u8, // FIXME: generalize?

        /// User PIN
        #[clap(long)]
        pin: Option<String>,

        /// Pgp key type.
        #[clap(long)]
        pkt: PgpKeyType,

        #[clap(short, long)]
        verbose: bool,
    },

    /// Sign via PKCS #11
    Sign {
        /// PKCS #11 device serial
        #[clap(long)]
        serial: String,

        /// Object ID
        #[clap(long)]
        id: u8, // FIXME: generalize to Vec<u8>?

        /// User PIN
        #[clap(long, default_value = "123456")]
        pin: String,

        /// OpenPGP certificate file
        ///
        /// When this parameter is available, additional OpenPGP key metadata
        /// is retrieved from the OpenPGP certificate.
        ///
        /// (If no certificate file is provided, additional OpenPGP
        /// metadata is retrieved from the X.509 certificate on the card,
        /// if available)
        #[clap(long)]
        cert: Option<PathBuf>,
    },

    /// Decrypt via PKCS #11
    Decrypt {
        /// PKCS #11 device serial
        #[clap(long)]
        serial: String,

        /// Object ID
        #[clap(long)]
        id: u8, // FIXME: generalize to Vec<u8>?

        /// User PIN
        #[clap(long, default_value = "123456")]
        pin: String,

        /// OpenPGP certificate file
        ///
        /// When this parameter is available, additional OpenPGP key metadata
        /// is retrieved from the OpenPGP certificate.
        ///
        /// (If no certificate file is provided, additional OpenPGP
        /// metadata is retrieved from the X.509 certificate on the card,
        /// if available)
        #[clap(long)]
        cert: Option<PathBuf>,
    },

    /// Upload an OpenPGP component key to a PKCS #11 card
    Upload {
        /// PKCS #11 device serial
        #[clap(long)]
        serial: String,

        /// Object ID
        #[clap(long)]
        id: u8, // FIXME: generalize to Vec<u8>?

        /// User PIN (may be needed, depending on the device)
        #[clap(long)]
        pin: Option<String>,

        /// So PIN (may be needed, depending on the device)
        #[clap(long)]
        so_pin: Option<String>,

        /// Path to an OpenPGP private key for uploading
        #[clap(long)]
        key: PathBuf,

        /// Component key fingerprint.
        #[clap(long)]
        fingerprint: Option<String>,

        /// Pgp key type.
        ///
        /// If 'key' has exactly one component key of the selected
        /// type, the component key is automatically chosen.
        /// Otherwise, the fingerprint parameter is required.
        #[clap(long)]
        pkt: Option<PgpKeyType>,
    },

    /// Print detailed PKCS #11 object metadata for inspection.
    ///
    /// This function is intended for debugging purposes, not for normal
    /// operation.
    Dump {
        /// PKCS#11 device serial
        #[clap(long)]
        serial: String,

        /// User PIN (some HSMs require the PIN for reading object data)
        #[clap(long)]
        pin: Option<String>,
    },
}

fn dump(module: &str, serial: String, pin: Option<String>) -> Result<()> {
    let mut card = Op11::open(module)?;
    let card_slot = card.slot(&serial)?;
    if let Ok(session) = card_slot.open_ro_session() {
        if let Some(pin) = pin {
            session.login(&pin)?;
        }

        let objs = session.session().find_objects(&[])?;

        println!("{objs:?}");

        for o in objs {
            println!("Object {o:x?}:");

            let attrs = session.session().get_attributes(
                o,
                &[
                    AttributeType::Id,
                    AttributeType::Class,
                    AttributeType::Application,
                    AttributeType::ObjectId,
                    AttributeType::KeyType,
                ],
            )?;

            for a in &attrs {
                match a {
                    Attribute::Id(id) => {
                        println!("Id: {id:x?}")
                    }
                    Attribute::Class(c) => {
                        println!("Class: {c}")
                    }
                    Attribute::KeyType(kt) => {
                        println!("KeyType: {kt}")
                    }
                    Attribute::Application(a) => {
                        let a = String::from_utf8_lossy(a);
                        println!("Application: {a}",)
                    }
                    Attribute::ObjectId(x) => {
                        println!("ObjectId: {x:x?}",)
                    }
                    _ => {
                        println!("[unexpected attribute] {a:?}")
                    }
                }
            }
            println!();
        }
    }

    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();

    let args = Cli::parse();
    match args.cmd {
        Command::List {} => {
            let pkcs11 = Op11::open(&args.module)?;
            for slot in pkcs11.pkcs11().get_slots_with_token()? {
                println!("{}", pkcs11.pkcs11().get_token_info(slot)?.serial_number());
            }
        }

        Command::Show {
            serial,
            id,
            pin,
            pkt,
            verbose,
        } => {
            // Get key via PKCS11, as a PGP subkey.
            let mut card = Op11::open(&args.module)?;
            let card_slot = card.slot(&serial)?;
            if let Ok(session) = card_slot.open_ro_session() {
                if let Some(pin) = pin {
                    session.login(&pin)?;
                }

                let key = session.key(
                    &[id],
                    pkt,
                    None, // FIXME: pass optional cert
                )?;

                println!("PKCS11 {id:?} key FP {key}");

                if verbose {
                    println!("\n{key:#x?}");
                }
            } else {
                return Err(anyhow::anyhow!("Couldn't open_ro_session for this slot").into());
            }
        }

        Command::Sign {
            serial,
            pin,
            cert,
            id,
        } => {
            let cert = cert.map(Cert::from_file).transpose()?;

            let mut pkcs11 = Op11::open(&args.module)?;
            let slot = pkcs11.slot(&serial)?;

            // open a read-write session, log in as user
            let session = slot.open_rw_session()?;
            session.login(&pin)?;

            // Use card SIG key via PKCS #11
            session.sign(&[id], &mut std::io::stdin(), &mut std::io::stdout(), cert)?;
        }

        Command::Decrypt {
            serial,
            pin,
            cert,
            id,
        } => {
            let cert = cert.map(Cert::from_file).transpose()?;

            let mut pkcs11 = Op11::open(&args.module)?;
            let slot = pkcs11.slot(&serial)?;

            // Open a read-write session, log in as user
            let session = slot.open_rw_session()?;
            session.login(&pin)?;

            session.decrypt(&[id], &mut std::io::stdin(), &mut std::io::stdout(), cert)?;
        }

        Command::Upload {
            serial,
            id,
            pin,
            so_pin,
            key,
            fingerprint: fp,
            pkt,
        } => {
            let cert = sequoia_openpgp::Cert::from_file(key)?;

            let sp = StandardPolicy::new();
            let vc = cert.with_policy(&sp, None)?;
            let user_id = vc.primary_userid()?;

            let cn = String::from_utf8_lossy(user_id.value());

            let subkey = if let Some(fp) = fp {
                let fp = Fingerprint::from_str(&fp)?;
                get_subkey_by_fp(&cert, fp)?
            } else if let Some(pkt) = pkt {
                get_subkey(&cert, pkt)?
            } else {
                return Err(anyhow::anyhow!(
                    "Either 'Pgp key type' or 'Fingerprint' must be provided"
                )
                .into());
            };

            log::info!("will upload {} to id {id}", subkey.fingerprint());

            let mut pkcs11 = Op11::open(&args.module)?;
            let slot = pkcs11.slot(&serial)?;

            // open a read-write session
            let session = slot.open_rw_session()?;

            // Log in as User or So, depending on clap parameters.
            // (YubiHSM only uses the User PIN, other cards require the So PIN)
            if let Some(pin) = pin {
                session.login(&pin)?;
            }
            if let Some(so_pin) = so_pin {
                session.login_so(&so_pin)?;
            }

            session.upload_key(&[id], &subkey, &cn)?;

            println!();
            println!(
                "Uploaded component key {}\nto serial '{}', PKCS#11 slot {}",
                subkey.fingerprint(),
                serial,
                id
            );
        }

        Command::Dump { serial, pin } => {
            dump(&args.module, serial, pin)?;
        }
    }

    Ok(())
}

/// Get subkey (with private key material) from cert
fn get_subkey_by_fp(
    cert: &Cert,
    fp: Fingerprint,
) -> Result<ValidErasedKeyAmalgamation<SecretParts>> {
    const P: &StandardPolicy = &StandardPolicy::new();

    // Get usable subkeys with secret key material
    let valid_ka = cert
        .keys()
        .with_policy(P, None)
        .secret()
        .alive()
        .revoked(false)
        .filter(|c| c.fingerprint() == fp);

    // Only return key if we found *exactly* one match for the requested functionality.
    let mut vkas: Vec<_> = valid_ka.collect();
    if vkas.len() == 1 {
        Ok(vkas.remove(0))
    } else {
        Err(anyhow::anyhow!(
            "Didn't find exactly one component key for '{:?}'",
            fp
        ))
    }
}

/// Get subkey (with private key material) from cert
fn get_subkey(cert: &Cert, pkt: PgpKeyType) -> Result<ValidErasedKeyAmalgamation<SecretParts>> {
    const P: &StandardPolicy = &StandardPolicy::new();

    // Get usable subkeys with secret key material
    let valid_ka = cert
        .keys()
        .with_policy(P, None)
        .secret()
        .alive()
        .revoked(false);

    // Pick out subkey for the functionality of 'slot'
    let valid_ka = match pkt {
        PgpKeyType::Sign => valid_ka.for_signing(),
        PgpKeyType::Auth => valid_ka.for_authentication(),
        PgpKeyType::Encrypt => valid_ka.for_storage_encryption().for_transport_encryption(),
    };

    // Only return key if there's *exactly* one suitable match for type 'slot',
    // otherwise error.
    let mut vkas: Vec<_> = valid_ka.collect();
    if vkas.len() == 1 {
        Ok(vkas.remove(0))
    } else {
        Err(anyhow::anyhow!(
            "Didn't find exactly one component key for '{:?}'",
            pkt
        ))
    }
}
