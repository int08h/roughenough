//! Compare performance of Ed25519 signature implementations

fn main() {
    divan::main();
}

/// Size of data being signed
const SIZES: &[usize] = &[32, 64, 128, 256, 512, 1024, 1024*1024];
/// Ed25519 seed
const SEED: [u8; 32] = [0x1a; 32];

trait BenchSigner {
    fn sign(&self, msg: &[u8]);
}

struct AwsLcSigner(aws_lc_rs::signature::Ed25519KeyPair);
struct DalekSigner(ed25519_dalek::SigningKey);

impl AwsLcSigner {
    pub fn new(seed: &[u8]) -> Self {
        let pair = aws_lc_rs::signature::Ed25519KeyPair::from_seed_unchecked(seed).unwrap();
        Self(pair)
    }
}

impl BenchSigner for AwsLcSigner {
    #[inline(always)]
    fn sign(&self, msg: &[u8]) {
        divan::black_box_drop(self.0.sign(msg))
    }
}

impl DalekSigner {
    pub fn new(seed: &[u8]) -> Self {
        let secret_key = ed25519_dalek::SecretKey::try_from(seed).unwrap();
        let signing_key = ed25519_dalek::SigningKey::from(secret_key);
        Self(signing_key)
    }
}

impl BenchSigner for DalekSigner {
    #[inline(always)]
    fn sign(&self, msg: &[u8]) {
        use ed25519_dalek::Signer;
        divan::black_box_drop(self.0.sign(msg))
    }
}

#[divan::bench(args = SIZES, min_time = 1.0)]
fn sig_awslc(bencher: divan::Bencher, len: usize)
{
    let signer = AwsLcSigner::new(&SEED);
    let bytes: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();

    bencher
        .with_inputs(|| bytes.clone())
        .bench_refs(|bytes| divan::black_box(signer.sign(bytes)))

}

#[divan::bench(args = SIZES, min_time = 1.0)]
fn sig_dalek(bencher: divan::Bencher, len: usize)
{
    let signer = DalekSigner::new(&SEED);
    let bytes: Vec<u8> = (0..len).map(|_| rand::random::<u8>()).collect();

    bencher
        .with_inputs(|| bytes.clone())
        .bench_refs(|bytes| divan::black_box(signer.sign(bytes)))

}
