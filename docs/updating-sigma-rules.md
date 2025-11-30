# Updating SIGMA Rules

The SIGMA detection rules are maintained as a Git submodule with sparse checkout, pulling only the Windows rules from the official [SigmaHQ repository](https://github.com/SigmaHQ/sigma).

## Update to Latest Rules

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

## Current Configuration

- **Submodule**: `src/sigma-master`
- **Source**: https://github.com/SigmaHQ/sigma.git
- **Sparse Checkout**: Only `rules/windows/*` directory
- **Bundled Output**: `public/sigma-rules/*.json`

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
