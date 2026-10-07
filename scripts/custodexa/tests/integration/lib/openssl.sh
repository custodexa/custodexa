# shellcheck shell=bash
# Three openssl builds, each in its own image (keys of images.txt):
#   3.5.4  alpine/openssl, the image the release pins and ships in every offline bundle
#   3.5.7  the bats test image (Debian), the tool the bats suite meets
#   1.1.1  Alpine 3.15, the oldest line the manual decryption commands claim to support
# it_openssl <3.5.4|3.5.7|1.1.1> <openssl arguments>: no network, stdin passed through, /it/work
# mounted at /work as the working directory.

# shellcheck disable=SC2034 # read by the scenarios
readonly IT_OPENSSL_VERSIONS="3.5.4 3.5.7 1.1.1"

it_openssl() {
  local img
  img=$(it_image "openssl-$1")
  shift
  mkdir -p "$IT_WORK/work"
  docker run --rm -i --pull never --network none -v "$IT_WORK/work:/work" -w /work \
    --entrypoint openssl "$img" "$@"
}
