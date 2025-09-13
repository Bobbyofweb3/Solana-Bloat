use sha2::{Digest, Sha256};
use hex::ToHex;
use anyhow::{Result, bail};

/// Simple helper: SHA256 of bytes
fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let res = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&res);
    out
}

/// Convert hash to hex short string for printing
fn h(h: &[u8;32]) -> String {
    h.encode_hex::<String>()[..16].to_string()
}

/// Chunk an arbitrary blob into fixed-size leaves (padding last chunk with zeros)
fn chunk_blob(blob: &[u8], chunk_size: usize) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < blob.len() {
        let end = std::cmp::min(i + chunk_size, blob.len());
        let mut chunk = blob[i..end].to_vec();
        if chunk.len() < chunk_size {
            chunk.resize(chunk_size, 0);
        }
        out.push(chunk);
        i += chunk_size;
    }
    // If blob is empty, still create a single zero chunk to avoid empty tree issues
    if out.is_empty() {
        out.push(vec![0u8; chunk_size]);
    }
    out
}

/// Simple Merkle tree implementation (binary). Leaves are hash(chunk).
#[derive(Debug)]
struct MerkleTree {
    /// layers[0] = leaves hashes, last layer = root (single element)
    layers: Vec<Vec<[u8;32]>>,
}

impl MerkleTree {
    /// Build tree from raw leaves (pre-hashed chunks are allowed; we hash chunk bytes ourselves)
    fn from_chunks(chunks: &[Vec<u8>]) -> Self {
        let mut leaves: Vec<[u8;32]> = chunks.iter().map(|c| sha256(c)).collect();
        // If number of leaves is not power of two, duplicate last leaf (simple padding)
        let mut n = leaves.len();
        if n & (n-1) != 0 {
            // round up to next power of two
            let mut pow = 1;
            while pow < n { pow <<= 1; }
            while leaves.len() < pow {
                leaves.push(*leaves.last().unwrap());
            }
            n = pow;
        }
        let mut layers = vec![leaves];
        // build upper layers
        while layers.last().unwrap().len() > 1 {
            let prev = layers.last().unwrap();
            let mut next = Vec::with_capacity((prev.len()+1)/2);
            for pair in prev.chunks(2) {
                let left = pair[0];
                let right = pair[1];
                let mut data = [0u8; 64];
                data[..32].copy_from_slice(&left);
                data[32..].copy_from_slice(&right);
                next.push(sha256(&data));
            }
            layers.push(next);
        }
        MerkleTree { layers }
    }

    /// Root of tree
    fn root(&self) -> [u8;32] {
        self.layers.last().unwrap()[0]
    }

    /// Produce proof for leaf index (original chunk index)
    /// Proof is Vec<(sibling_hash, is_left_sibling?)>
    fn gen_proof(&self, leaf_index: usize) -> Vec<([u8;32], bool)> {
        let mut proof = Vec::new();
        let mut idx = leaf_index;
        for layer in &self.layers {
            if layer.len() == 1 { break; }
            let pair_idx = if idx % 2 == 0 { idx + 1 } else { idx - 1 };
            let sibling = layer[pair_idx];
            let is_left = pair_idx < idx; // sibling is left of our node?
            proof.push((sibling, is_left));
            idx /= 2;
        }
        proof
    }

    /// Verify a proof for a given leaf chunk and expected root
    fn verify_proof(leaf_chunk: &[u8], proof: &Vec<([u8;32], bool)>, expected_root: &[u8;32]) -> bool {
        let mut computed = sha256(leaf_chunk);
        for (sibling, is_left) in proof {
            let mut data = [0u8; 64];
            if *is_left {
                // sibling is left, so sibling || computed
                data[..32].copy_from_slice(sibling);
                data[32..].copy_from_slice(&computed);
            } else {
                // computed || sibling
                data[..32].copy_from_slice(&computed);
                data[32..].copy_from_slice(sibling);
            }
            computed = sha256(&data);
        }
        &computed == expected_root
    }
}

/// A toy "on-chain" stub that stores the merkle root of an account blob
#[derive(Debug, Clone)]
struct AccountStub {
    pub owner: String,       // owner pubkey placeholder
    pub lamports: u64,       // lamports balance (fake)
    pub merkle_root: [u8;32],// commitment to full blob
}

impl AccountStub {
    fn new(owner: &str, lamports: u64, merkle_root: [u8;32]) -> Self {
        Self { owner: owner.to_string(), lamports, merkle_root }
    }
}

/// Simulated "blockchain state" mapping pubkey -> stub
use std::collections::HashMap;
struct ChainState {
    stubs: HashMap<String, AccountStub>,
}

impl ChainState {
    fn new() -> Self { Self { stubs: HashMap::new() } }

    fn put_stub(&mut self, pubkey: &str, stub: AccountStub) {
        self.stubs.insert(pubkey.to_string(), stub);
    }

    fn get_stub(&self, pubkey: &str) -> Option<&AccountStub> {
        self.stubs.get(pubkey)
    }

    /// Process a transaction that carries:
    /// - pubkey of account to act on
    /// - full blob bytes (account bytes)
    /// - proofs for each leaf (we simplify: provide proof for the first leaf and trust the blob matches the root if proof verifies)
    ///
    /// If verification passes, we "apply" the transaction: compute new root and update stub.
    fn process_tx_witness(&mut self, pubkey: &str, blob: &[u8], chunk_size: usize, proof_for_index: usize, proof: &Vec<([u8;32], bool)>) -> Result<()> {
        // read stub
        let stub = match self.stubs.get(pubkey) {
            Some(s) => s.clone(),
            None => bail!("no stub for pubkey {}", pubkey),
        };
        // chunk blob and pick the leaf chunk for which proof was provided
        let chunks = chunk_blob(blob, chunk_size);
        if proof_for_index >= chunks.len() {
            bail!("proof index {} out of range ({} chunks)", proof_for_index, chunks.len());
        }
        let leaf_chunk = &chunks[proof_for_index];

        // verify proof against stub.merkle_root
        let ok = MerkleTree::verify_proof(leaf_chunk, proof, &stub.merkle_root);
        if !ok {
            bail!("proof verification failed");
        }
        println!("✅ Proof verified for pubkey {} leaf {} (stub root {})", pubkey, proof_for_index, h(&stub.merkle_root));

        // For demo: mutate the blob in a deterministic way (toggle first byte), recompute new root
        let mut new_blob = blob.to_vec();
        if new_blob.is_empty() {
            new_blob.push(1u8);
        } else {
            new_blob[0] = new_blob[0].wrapping_add(1);
        }
        let new_chunks = chunk_blob(&new_blob, chunk_size);
        let new_tree = MerkleTree::from_chunks(&new_chunks);
        let new_root = new_tree.root();
        // update stub on "chain"
        let new_stub = AccountStub::new(&stub.owner, stub.lamports, new_root);
        self.stubs.insert(pubkey.to_string(), new_stub);
        println!("🔁 Applied tx: updated merkle root -> {}", h(&new_root));
        Ok(())
    }
}

fn main() -> Result<()> {
    println!("=== Account Witness Prototype ===");

    // Example account blob (metadata or large account data)
    let account_blob = b"Example account blob: this could be an NFT metadata JSON or game state. It's larger than a chunk so we create multiple leaves.".to_vec();
    let chunk_size = 32;

    // Build merkle tree representing the on-chain commitment
    let chunks = chunk_blob(&account_blob, chunk_size);
    let tree = MerkleTree::from_chunks(&chunks);
    let root = tree.root();
    println!("Initial merkle root: {}", h(&root));
    println!("Leaf count (after padding to power of two): {}", tree.layers[0].len());

    // Create an on-chain stub for pubkey "Acct1"
    let mut chain = ChainState::new();
    let stub = AccountStub::new("owner_pubkey_1", 1_000, root);
    chain.put_stub("Acct1", stub);
    println!("Stored stub for Acct1.");

    // Simulate client constructing a tx:
    // choose a leaf index (0) and get proof from tree
    let leaf_index = 0usize;
    let proof = tree.gen_proof(leaf_index);
    println!("Proof length for leaf {}: {}", leaf_index, proof.len());

    // Print proof skeleton (short hashes)
    for (i, (sibling, is_left)) in proof.iter().enumerate() {
        println!("  proof[{}] sibling {} is_left {}", i, h(sibling), is_left);
    }

    // Now process a tx on-chain that includes: full blob + proof for leaf_index
    println!("\nProcessing transaction that carries full blob + proof...");
    chain.process_tx_witness("Acct1", &account_blob, chunk_size, leaf_index, &proof)?;

    // Show updated stub
    let new_stub = chain.get_stub("Acct1").unwrap();
    println!("Final stub merkle root stored on chain: {}", h(&new_stub.merkle_root));

    Ok(())
}
