//! A researcher's `did:bio` identity delegates read access to a device's
//! post-quantum `did:key`, with the blob's content key wrapped inside the
//! same signed UCAN; the device then exercises the grant.

use std::collections::BTreeMap;

use pq_space::{space_aad, BioResolver, BioSigner, Network, SpaceKeyPair, WrappedContentKey};
use pq_ucan::{
    command::Command,
    crypto::{ed25519::Ed25519Keypair, ml_dsa::MlDsaKeypair, Algorithm, Signer},
    delegation::{Delegation, Subject},
    did::Did,
    invocation::Invocation,
    nonce::Nonce,
    time::Timestamp,
    validate::{MemoryStore, Validator},
    Ipld,
};
use testresult::TestResult;

const COMMAND: &str = "/space/blob/get";

#[test]
fn bio_issuer_delegates_wrapped_key_to_pq_device() -> TestResult {
    let researcher = BioSigner::from_seed(Network::Devnet, &[5u8; 32])?;
    let space = researcher.did();
    let device = MlDsaKeypair::from_seed(Algorithm::MlDsa87, &[6u8; 32])?;
    let device_kem = SpaceKeyPair::generate()?;
    let now = Timestamp::from_unix(1_800_000_000)?;

    let content_key = [42u8; 32];
    let aad = space_aad(space.as_str(), COMMAND);
    let wrapped =
        WrappedContentKey::wrap(&device_kem.encapsulation_key_bytes()?, &content_key, &aad)?;
    let mut meta = BTreeMap::new();
    wrapped.attach_to_meta(&mut meta);

    let delegation = Delegation::builder(
        device.did(),
        Subject::Did(space.clone()),
        Command::parse(COMMAND)?,
    )
    .meta(meta)
    .nonce(Nonce::from_bytes(&[1u8; 12]))
    .expires_at(now.plus_seconds(3600))
    .sign(&researcher)?;

    // The bytes reach the device, which decodes and verifies them.
    let received = Delegation::decode(delegation.bytes())?;
    received.verify(&BioResolver)?;
    assert_eq!(received.issuer(), &space);
    assert_eq!(received.audience(), &device.did());
    assert_eq!(
        pq_space::bio_of(received.issuer()).map(|b| b.network),
        Some(Network::Devnet)
    );

    // A stranger's key does not verify.
    let stranger = Ed25519Keypair::from_seed(&[9u8; 32]);
    assert!(received.envelope().verify(stranger.public_key()).is_err());

    let carried = WrappedContentKey::from_meta(received.meta()).expect("wrapped key attached")?;
    assert_eq!(carried.unwrap_key(&device_kem, &aad)?, content_key);

    // A copy pasted into a different grant does not open.
    let other_aad = space_aad(space.as_str(), "/space/blob/list");
    assert!(carried.unwrap_key(&device_kem, &other_aad).is_err());

    // The device exercises the grant and the space validates the chain.
    let invocation = Invocation::builder(space.clone(), Command::parse(COMMAND)?)
        .arg("blob", Ipld::String("bafy".into()))
        .proof(*received.cid())
        .nonce(Nonce::from_bytes(&[2u8; 12]))
        .expires_at(now.plus_seconds(60))
        .sign(&device)?;
    let mut store = MemoryStore::new();
    store.insert(received);
    let proof = Validator::new(&store, now)
        .resolver(&BioResolver)
        .executor(&space)
        .validate(&invocation)?;
    assert_eq!(proof.chain().len(), 1);
    Ok(())
}

#[test]
fn owner_publishes_a_key_a_stranger_can_wrap_to() -> TestResult {
    // The wrapper never meets the recipient: it reads the encapsulation
    // key from a DID document service entry.
    let owner = SpaceKeyPair::generate()?;
    let published = owner.encapsulation_key_multibase()?;
    assert_eq!(pq_space::SPACE_KEY_SERVICE_TYPE, "SpaceEncapsulationKey");

    let space = Did::parse("did:bio:devnet:2T6zLFvMx7NJac5qQtiKTaPhMwHLkwKETWjUK1yKv4tc")?;
    let aad = space_aad(space.as_str(), COMMAND);
    let content_key = [11u8; 32];

    let encapsulation_key = pq_space::decode_encapsulation_key(&published)?;
    let wrapped = WrappedContentKey::wrap(&encapsulation_key, &content_key, &aad)?;

    assert_eq!(wrapped.unwrap_key(&owner, &aad)?, content_key);
    Ok(())
}

#[test]
fn pq_device_re_delegates_with_ml_dsa_signature() -> TestResult {
    // The device re-delegates to a colleague, signing with ML-DSA-87.
    let device = MlDsaKeypair::from_seed(Algorithm::MlDsa87, &[6u8; 32])?;
    let colleague = Ed25519Keypair::from_seed(&[7u8; 32]);
    let space = BioSigner::from_seed(Network::Devnet, &[5u8; 32])?.did();

    let delegation = Delegation::builder(
        colleague.did(),
        Subject::Did(space),
        Command::parse(COMMAND)?,
    )
    .nonce(Nonce::from_bytes(&[3u8; 12]))
    .expires_at(Timestamp::from_unix(1_800_000_000)?)
    .sign(&device)?;

    let received = Delegation::decode(delegation.bytes())?;
    received.verify(&BioResolver)?;
    assert!(received.algorithm().is_post_quantum());

    // The 4627 byte signature dominates the token.
    assert!(received.bytes().len() > 4627);
    Ok(())
}
