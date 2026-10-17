# Synthetic upload-action archives

Generated on 2026-10-17 by the pinned `actions/upload-artifact` bundle at
`ea165f8d65b6e75b540449e92b4886f43607fa02`, original `dist/upload/index.js`
SHA-256 `0165b8a75330f3228f2c7a234b4ff8a107b9139c2b519147f4c8e9fe99b262d8`.
Only its startup module selection changed from action entry `36664` to ZIP helper
`69186`; the original action startup was not executed. The independently checked
static closure contained 347 bundled modules. Compression level: zero.

- `producer.zip`: 4,631 bytes; SHA-256 `34497e87b4aff7c02dc3390510c67e8a96ecfe82d4442382ff587a014de20474`.
- `sealed.zip`: 888 bytes; SHA-256 `902bbc3da82579a5259c2685d7d4a32442297cb3873401ff28c7c4c90dba6cfc`.

Inputs are the reviewed synthetic source/seal qualification records, including a
placeholder attestation. They contain no credentials, genuine review findings or
valid signed evidence. The test pins each recovered file digest.

The one controlled writer attempt passed inside a restricted offline sandbox:
owner-file reads, network and child-process creation were denied; all frozen
source hashes remained unchanged and the owned process exited. These fixtures
prove ZIP compatibility only. They establish no cryptographic verification,
hosted runtime provenance, network transfer or production activation.
