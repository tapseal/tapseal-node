#!/bin/sh
# TAPSEAL audited user-local installer. Published bootstrap pins one release hash.
set -eu
umask 077
RELEASE_URL="${TAPSEAL_RELEASE_URL:-https://tapseal.xyz/node/tapseal-node-1.2.0-networks.1.tar.gz}"
RELEASE_SHA256="${TAPSEAL_RELEASE_SHA256:-__PINNED_RELEASE_SHA256__}"
HOME_DIR="${TAPSEAL_HOME:-$HOME/.tapseal}"
BIN_DIR="${TAPSEAL_BIN:-$HOME/.local/bin}"
TAPSEAL_TMP="";TAPSEAL_STAGE=""
cleanup(){ [ -z "$TAPSEAL_TMP" ] || rm -rf "$TAPSEAL_TMP";[ -z "$TAPSEAL_STAGE" ] || rm -rf "$TAPSEAL_STAGE"; }
trap cleanup EXIT
fail(){ printf 'error: %s\n' "$*" >&2;exit 1; }
[ "$(id -u)" != 0 ] || [ "${TAPSEAL_INSTALL_ALLOW_ROOT:-0}" = 1 ] || fail 'Install as your regular user, without sudo. Vultr uses the separate upgrade script.'
case "$HOME_DIR" in ''|/|/etc|/usr|/opt|/var|/root) fail 'Choose a dedicated TAPSEAL_HOME directory.';;esac
SERVICE=0;WINTASK=""
for arg in "$@";do shift;case "$arg" in --service)SERVICE=1;;--windows-task)WINTASK="--windows-task";;*)set -- "$@" "$arg";;esac;done
command -v python3 >/dev/null 2>&1 || fail 'Python 3.10+ is required.'
python3 -c 'import sys;sys.exit(0 if sys.version_info>=(3,10) else 1)' || fail 'Python 3.10+ is required.'
command -v node >/dev/null 2>&1 || fail 'Node.js 22+ is required.'
[ "$(node -p 'process.versions.node.split(".")[0]')" -ge 22 ] || fail 'Node.js 22+ is required.'
command -v npm >/dev/null 2>&1 || fail 'npm is required.'
here="$(cd "$(dirname "$0")" 2>/dev/null && pwd || true)"
if [ -n "$here" ] && [ -f "$here/app/api/server.js" ];then
 src="$here"
else
 case "$RELEASE_URL" in https://*) ;;*)fail 'The release URL must use HTTPS.';;esac
 python3 -c 'import re,sys;sys.exit(0 if re.fullmatch("[0-9a-f]{64}",sys.argv[1]) else 1)' "$RELEASE_SHA256" || fail 'A pinned release SHA-256 is required. Use the official published installer.'
 TAPSEAL_TMP="$(mktemp -d)"
 command -v curl >/dev/null 2>&1 || fail 'curl is required for HTTPS downloads.'
 curl --proto '=https' --proto-redir '=https' --tlsv1.2 --connect-timeout 15 --max-time 180 --max-filesize 33554432 -fsSL "$RELEASE_URL" -o "$TAPSEAL_TMP/release.tgz"
 src="$(python3 - "$TAPSEAL_TMP/release.tgz" "$RELEASE_SHA256" "$TAPSEAL_TMP" <<'PY'
import hashlib,pathlib,re,sys,tarfile
archive=pathlib.Path(sys.argv[1]);expected=sys.argv[2];base=pathlib.Path(sys.argv[3]).resolve()
if hashlib.sha256(archive.read_bytes()).hexdigest()!=expected:raise SystemExit('release checksum mismatch')
with tarfile.open(archive,'r:gz') as t:
 members=[];roots=set();size=0
 for m in t:
  if len(members)>=10000:raise SystemExit('too many archive members')
  members.append(m)
  p=pathlib.PurePosixPath(m.name)
  if p.is_absolute() or '..' in p.parts or not p.parts or not (m.isfile() or m.isdir()):raise SystemExit('unsafe archive member')
  roots.add(p.parts[0]);size+=m.size
  if size>64*1024*1024:raise SystemExit('archive exceeds extraction limit')
 if len(roots)!=1 or not re.fullmatch(r'tapseal-node-[A-Za-z0-9.-]+',next(iter(roots))):raise SystemExit('unexpected release layout')
 # All members are regular files/directories; links and traversal were rejected above.
 t.extractall(base,members=members)
 src=base/next(iter(roots))
 if not (src/'app/api/server.js').is_file():raise SystemExit('incomplete release')
 print(src)
PY
 )"
fi
mkdir -p "$HOME_DIR" "$BIN_DIR";chmod 700 "$HOME_DIR"
[ ! -e "$BIN_DIR/tapseal-node" ] || [ -L "$BIN_DIR/tapseal-node" ] || fail 'A different tapseal-node command exists. Choose TAPSEAL_BIN.'
TAPSEAL_STAGE="$(mktemp -d "$HOME_DIR/.install-XXXXXX")"
cp -R "$src/app" "$TAPSEAL_STAGE/app";chmod +x "$TAPSEAL_STAGE/app/bin/tapseal-node"
printf 'Installing dependencies in a staging directory; current app and data stay intact.\n'
(cd "$TAPSEAL_STAGE/app/api" && npm ci --omit=dev --no-audit --no-fund --loglevel=error) || fail 'Dependency installation failed; current application was not replaced.'
python3 "$TAPSEAL_STAGE/app/bin/tapseal-node" --version >/dev/null
previous="$HOME_DIR/app.previous-$(date +%Y%m%d%H%M%S)-$$"
if [ -d "$HOME_DIR/app" ];then mv "$HOME_DIR/app" "$previous";fi
if ! mv "$TAPSEAL_STAGE/app" "$HOME_DIR/app";then
 [ ! -d "$previous" ] || mv "$previous" "$HOME_DIR/app"
 fail 'Application replacement failed; previous version restored.'
fi
ln -sf "$HOME_DIR/app/bin/tapseal-node" "$BIN_DIR/tapseal-node"
if [ -f "$HOME_DIR/node.json" ] && [ "$#" -eq 0 ];then
 printf 'Kept existing node settings and data.\n'
else
 TAPSEAL_HOME="$HOME_DIR" "$HOME_DIR/app/bin/tapseal-node" init "$@"
fi
printf 'Installed: %s\nCommand: %s\n' "$HOME_DIR" "$BIN_DIR/tapseal-node"
if [ "$SERVICE" = 1 ];then TAPSEAL_HOME="$HOME_DIR" "$HOME_DIR/app/bin/tapseal-node" service install $WINTASK
else printf 'Start: %s start\n' "$BIN_DIR/tapseal-node";fi
printf 'Light mode is read-only and depends on block APIs. Peer reports are unauthenticated; seal roots do not commit the full ledger.\n'
