#!/bin/sh
# Makes the SDK's Qt and the BaseApp's Qt WebEngine (under /app) look like
# one installation to cxx-qt-build, which asks qmake for one library and one
# header directory and expects a .prl file there for every module.
#
# Writes <dir>/qmake, a wrapper that answers QT_INSTALL_LIBS and
# QT_INSTALL_HEADERS with directories of symlinks to both, and passes every
# other query to the SDK's qmake. Nothing is copied or changed in /usr or
# /app. Usage: qt-for-app.sh <dir>; then build with QMAKE=<dir>/qmake.
set -eu
dir=$1
real=$(command -v qmake6 || command -v qmake)
libs=$("$real" -query QT_INSTALL_LIBS)
headers=$("$real" -query QT_INSTALL_HEADERS)
engine=$(find /app -path '*/QtWebEngineCore/QWebEnginePage' -print -quit)
[ -n "$engine" ] || { echo "Qt WebEngine headers not found under /app" >&2; exit 1; }
engine_headers=$(dirname "$(dirname "$engine")")
engine_libs=$(dirname "$(find /app -name 'libQt6WebEngineCore.so*' -print -quit)")
echo "SDK Qt: $real, libraries $libs, headers $headers"
echo "Qt WebEngine: libraries $engine_libs, headers $engine_headers"
echo "WebEngine .prl files: $(find /app -name 'libQt6WebEngine*.prl' | tr '\n' ' ')"

rm -rf "$dir"
mkdir -p "$dir/lib" "$dir/include"
for f in "$libs"/libQt6* "$engine_libs"/libQt6*; do
  [ -e "$f" ] && ln -sf "$f" "$dir/lib/"
done
for d in "$headers"/* "$engine_headers"/Qt*; do
  [ -e "$d" ] && ln -sfn "$d" "$dir/include/"
done
# A module without a .prl gets an empty one: its shared library names its
# own dependencies.
for module in WebEngineCore WebEngineWidgets; do
  [ -e "$dir/lib/libQt6$module.so" ] || { echo "libQt6$module.so not found" >&2; exit 1; }
  [ -e "$dir/lib/libQt6$module.prl" ] || printf 'QMAKE_PRL_LIBS =\n' > "$dir/lib/libQt6$module.prl"
done

cat > "$dir/qmake" <<EOF
#!/bin/sh
case "\$*" in
  "-query QT_INSTALL_LIBS") echo "$dir/lib" ;;
  "-query QT_INSTALL_HEADERS") echo "$dir/include" ;;
  *) exec "$real" "\$@" ;;
esac
EOF
chmod 755 "$dir/qmake"
