#!/usr/bin/env bash
set -euo pipefail
set -x
rsync -avz --exclude .git --exclude .idea --exclude target . ascii6:ipv6shell/

ssh ascii6 bash <<'EOF'
set -euo pipefail
set -x
cd ipv6shell
PATH="$HOME/.cargo/bin:$PATH"
cargo build --release
sudo systemctl restart shell6
EOF
