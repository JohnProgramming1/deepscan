#!/usr/bin/env bash
# deepscan installer for macOS and Linux
#   curl -fsSL https://raw.githubusercontent.com/YOUR-GITHUB-USERNAME/deepscan/main/install.sh | bash
set -euo pipefail

REPO="${DEEPSCAN_REPO:-JohnProgramming/deepscan}"
APP_DIR="$HOME/.deepscan/app"
BIN_DIR="$HOME/.local/bin"

say()  { printf '\033[1;36m==>\033[0m %s\n' "$*"; }
fail() { printf '\033[1;31merror:\033[0m %s\n' "$*" >&2; exit 1; }

# 1) find Python 3.8+
PY=""
for c in python3 python; do
  if command -v "$c" >/dev/null 2>&1 &&
     "$c" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
    PY="$c"; break
  fi
done
[ -n "$PY" ] || fail "deepscan needs Python 3.8 or newer. Get it from https://www.python.org/downloads/ and run this again."
say "Using $("$PY" --version 2>&1)"

# 2) private environment so it never clashes with your other Python stuff
say "Setting up in $APP_DIR"
rm -rf "$APP_DIR"
mkdir -p "$(dirname "$APP_DIR")"
"$PY" -m venv "$APP_DIR" ||
  fail "Couldn't create a Python environment. On Debian/Ubuntu, run: sudo apt install python3-venv"
"$APP_DIR/bin/python" -m pip install --quiet --upgrade pip

say "Downloading deepscan and installing it"
"$APP_DIR/bin/python" -m pip install --quiet "https://github.com/$REPO/archive/refs/heads/main.zip" ||
  fail "Install failed. Check your internet connection and that github.com/$REPO exists."

# 3) put the command on PATH
mkdir -p "$BIN_DIR"
ln -sf "$APP_DIR/bin/deepscan" "$BIN_DIR/deepscan"

case ":$PATH:" in
  *":$BIN_DIR:"*) ;;
  *)
    case "$(basename "${SHELL:-bash}")" in
      zsh)  RC="$HOME/.zshrc" ;;
      bash) if [ "$(uname)" = "Darwin" ]; then RC="$HOME/.bash_profile"; else RC="$HOME/.bashrc"; fi ;;
      *)    RC="$HOME/.profile" ;;
    esac
    if ! grep -qs 'added by deepscan installer' "$RC"; then
      printf '\nexport PATH="$HOME/.local/bin:$PATH"  # added by deepscan installer\n' >> "$RC"
    fi
    say "Added $BIN_DIR to your PATH in $RC"
    ;;
esac

echo
say "Installed! Open a new terminal window and run:  deepscan"
echo "    To update, run this installer again."
echo "    To uninstall:  rm -rf ~/.deepscan/app ~/.local/bin/deepscan"
