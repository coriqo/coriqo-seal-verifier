#!/usr/bin/env sh
# Build the GitHub Pages site into dist/: the files in web/, the version in the
# footer, and a SHA256SUMS an auditor can compare with the release and with the
# live site. No network, no dependencies. Run from the repository root:
#   sh web/build.sh
set -eu
cd "$(dirname "$0")/.."
VERSION="$(sed -n 's/^VERIFIER_VERSION = "\(.*\)"$/\1/p' verify_proof.py)"
[ -n "$VERSION" ] || { echo "VERIFIER_VERSION not found in verify_proof.py" >&2; exit 1; }
rm -rf dist && mkdir dist && mkdir dist/fonts
cp web/fonts/* dist/fonts/
for f in style.css page-ui.js verify.js verify-ui.js keyring.js sample.js seal.svg; do
  cp "web/$f" "dist/$f"
done
grep -q '<b id="ver">dev</b>' web/index.html || { echo "version placeholder missing in web/index.html" >&2; exit 1; }
sed "s|<b id=\"ver\">dev</b>|<b id=\"ver\">$VERSION</b>|" web/index.html > dist/index.html
(cd dist && find . -type f ! -name SHA256SUMS | LC_ALL=C sort | xargs shasum -a 256 > SHA256SUMS)
echo "built dist/ for v$VERSION"
