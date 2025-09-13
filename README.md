# # Solana State Bloat — Enduring Solutions

This repo contains my submission to the **Superteam Vietnam x Solana Bounty** on enduring solutions for account data storage.

## Contents
- **report.pdf** — Full research paper (8–10 pages)
- **slides.pdf** — Pitch deck version
- **prototype/** — Rust prototype demonstrating account witness verification
- **diagrams/** — Architecture diagrams

## Summary
Solana’s account model leads to ~500 GB of live state and ~400 TB of archival ledger,
pushing validator costs to $500–$1,000/month. Without addressing state growth, rent 
cannot be lowered and decentralization suffers.

This repo proposes three enduring solutions:

1. **Stateless On-Demand Witnesses**  
   Transactions carry account proofs (Merkle/KZG/Verkle), preserving CPI while reducing validator storage.

2. **Tiered State (Hot / Cold / Archive)**  
   Accounts can be “cold” with only a stub on-chain; thawed on demand via proofs.

3. **State Expiry + Optional Preservation**  
   Ephemeral accounts expire unless developers opt-in to pay for preservation.

## License
MIT — feel free to build on this research.
