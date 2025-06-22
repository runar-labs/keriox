use crate::{
    error::Error,
    keys::{PrivateKey, PublicKey},
};
use rand::rngs::OsRng;

#[cfg(feature = "wallet")]
pub mod wallet;

pub trait KeyManager {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error>;
    fn public_key(&self) -> Result<PublicKey, Error>;
    fn next_public_key(&self) -> Result<PublicKey, Error>;
    fn rotate(&mut self) -> Result<(), Error>;
}

pub struct CryptoBox {
    signer: Signer,
    next_priv_key: PrivateKey,
    pub next_pub_key: PublicKey,
}

impl KeyManager for CryptoBox {
    fn sign(&self, msg: &[u8]) -> Result<Vec<u8>, Error> {
        self.signer.sign(msg)
    }

    fn public_key(&self) -> Result<PublicKey, Error> {
        Ok(self.signer.pub_key.clone())
    }

    fn next_public_key(&self) -> Result<PublicKey, Error> {
        Ok(self.next_pub_key.clone())
    }

    fn rotate(&mut self) -> Result<(), Error> {
        let (next_pub_key, next_priv_key) = generate_key_pair()?;

        let new_signer = Signer {
            priv_key: self.next_priv_key.clone(),
            pub_key: self.next_pub_key.clone(),
        };
        self.signer = new_signer;
        self.next_priv_key = next_priv_key;
        self.next_pub_key = next_pub_key;

        Ok(())
    }
}

impl CryptoBox {
    pub fn new() -> Result<Self, Error> {
        let signer = Signer::new();
        let (next_pub_key, next_priv_key) = generate_key_pair()?;
        Ok(CryptoBox {
            signer,
            next_pub_key,
            next_priv_key,
        })
    }

    /// Extract the current private key bytes for secure storage
    pub fn current_private_key_bytes(&self) -> Vec<u8> {
        self.signer.priv_key.key()
    }

    /// Extract the next private key bytes for secure storage
    pub fn next_private_key_bytes(&self) -> Vec<u8> {
        self.next_priv_key.key()
    }

    /// Create a CryptoBox from existing private key bytes (for restoration from secure storage)
    pub fn from_private_keys(current_priv_bytes: Vec<u8>, next_priv_bytes: Vec<u8>) -> Result<Self, Error> {
        // Recreate the current keypair
        let current_priv_key = PrivateKey::new(current_priv_bytes);
        let current_pub_key = Self::derive_public_key_from_private(&current_priv_key)?;
        
        // Recreate the next keypair
        let next_priv_key = PrivateKey::new(next_priv_bytes);
        let next_pub_key = Self::derive_public_key_from_private(&next_priv_key)?;

        let signer = Signer {
            priv_key: current_priv_key,
            pub_key: current_pub_key,
        };

        Ok(CryptoBox {
            signer,
            next_pub_key,
            next_priv_key,
        })
    }

    /// Derive public key from private key bytes
    fn derive_public_key_from_private(priv_key: &PrivateKey) -> Result<PublicKey, Error> {
        let secret_key = ed25519_dalek::SecretKey::from_bytes(&priv_key.key())?;
        let public_key = ed25519_dalek::PublicKey::from(&secret_key);
        Ok(PublicKey::new(public_key.to_bytes().to_vec()))
    }
}

struct Signer {
    priv_key: PrivateKey,
    pub pub_key: PublicKey,
}

impl Signer {
    pub fn new() -> Self {
        let ed = ed25519_dalek::Keypair::generate(&mut OsRng);
        let pub_key = PublicKey::new(ed.public.to_bytes().to_vec());
        let priv_key = PrivateKey::new(ed.secret.to_bytes().to_vec());

        Signer { pub_key, priv_key }
    }

    pub fn sign(&self, msg: impl AsRef<[u8]>) -> Result<Vec<u8>, Error> {
        self.priv_key.sign_ed(msg.as_ref())
    }
}

fn generate_key_pair() -> Result<(PublicKey, PrivateKey), Error> {
    let kp = ed25519_dalek::Keypair::generate(&mut OsRng {});
    let (vk, sk) = (kp.public, kp.secret);
    let vk = PublicKey::new(vk.to_bytes().to_vec());
    let sk = PrivateKey::new(sk.to_bytes().to_vec());
    Ok((vk, sk))
}
