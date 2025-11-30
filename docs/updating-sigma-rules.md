# Updating Detection Rules

LUMEN uses detection rules from multiple sources, maintained as Git submodules with sparse checkout.

## SIGMA Rules (Primary)

The SIGMA detection rules are maintained as a Git submodule with sparse checkout, pulling only the Windows rules from the official [SigmaHQ repository](https://github.com/SigmaHQ/sigma).

### Update to Latest SIGMA Rules

To pull the latest SIGMA rules from upstream:

```bash
# Update the submodule to latest from SigmaHQ
git submodule update --remote src/sigma-master

# Rebuild the bundled rules
npm run bundle:sigma

# Commit the updated rules
git add src/sigma-master public/sigma-rules
git commit -m "Update SIGMA rules to latest version"
```

## Chainsaw Rules (Reference)

Chainsaw's native tau detection rules are included as a reference. These are **not SIGMA format** and are not currently integrated into LUMEN's detection engine, but serve as valuable reference material for threat hunting patterns.

### Update Chainsaw Rules

```bash
# Update the submodule to latest from Chainsaw
git submodule update --remote src/chainsaw-rules

# Commit the updated rules
git add src/chainsaw-rules
git commit -m "Update Chainsaw detection rules"
```

## Current Configuration

### SIGMA Rules (Active)
- **Submodule**: `src/sigma-master`
- **Source**: https://github.com/SigmaHQ/sigma.git
- **Sparse Checkout**: Only `rules/windows/*` directory
- **Bundled Output**: `public/sigma-rules/*.json`
- **Rule Count**: ~2,356 Windows detection rules

### Chainsaw Rules (Reference)
- **Submodule**: `src/chainsaw-rules`
- **Source**: https://github.com/WithSecureLabs/chainsaw.git
- **Sparse Checkout**: Only `rules/evtx/*` directory
- **Format**: Chainsaw tau (not SIGMA)
- **Rule Count**: 74 Windows-focused detection rules

## Why Sparse Checkout?

The full SIGMA repository contains:
- Linux rules
- macOS rules
- Cloud provider rules
- Documentation
- Images and metadata
- Deprecated rules

Since LUMEN focuses on Windows Event Log analysis, we only need the Windows rules. Sparse checkout keeps our repository lean while maintaining the ability to pull updates from upstream.

## Manual Configuration

If you need to reconfigure the sparse checkout:

```bash
cd src/sigma-master
git config core.sparseCheckout true
echo "rules/windows/*" > ../../.git/modules/sigma-windows/info/sparse-checkout
git read-tree -mu HEAD
cd ../..
```
