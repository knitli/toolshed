# Native workspace guest inventory

The opt-in `--native-workspace-guest-inventory` flag on
`qualify_offline_macos_vm.py` collects preparation inputs after the existing
NIC-drop canary passes. Use it without the SCPreferences or Softnet DHCP flags
for an inventory-only run. The original protected base stays unchanged; the
controller stops, reaps, and disposes of its owned clone.

The fixed command runs as `admin:staff` with a cleared environment; the loader
resets it again before import because Apple's Python launcher can add variables
after `env -i`. A two-source bundle reuses the existing loader and bounded
runner under Apple Python 3.9.
It records Apple Python separately from available Homebrew interpreters, direct
Rust toolchain paths, stage tool and pkg-config versions, SDK metadata, disk/RAM,
and shallow metadata for the fixed Cargo/Rustup homes. It executes no Rustup or
Homebrew provisioner, Cargo fetch/build, or Apple developer-tool installer.

Each command and file read is bounded. One 24-second guest budget fits inside
the 30-second transport limit; later probes report budget exhaustion rather
than extending that budget. Missing tools and incomplete cache observations
are data. Directory byte counts are shallow and do not prove cache completeness.

The private raw report and stderr files are bound into `rawEvidence`. The report
binds both guest source hashes and retains `collectionOnly: true`,
`prepared: false`, and `nativeQualified: false`. A requested collection failure
is retained and fails the overall invocation while preserving the baseline
checks. A successful collection does not establish stage compatibility or
build fit.

Use the observations to choose the next reviewed preparation step in
[native workspace staging](native-workspace-staging.md). The current staging
command still requires provisioned tools and guest dependency acquisition;
this flag neither supplies inputs nor grants networking.
