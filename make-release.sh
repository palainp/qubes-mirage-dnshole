#!/bin/sh
set -eu

if [ $# -ne 2 ] ; then
  echo "Usage: make-release.sh VERSION { docker | podman }"
  exit 1
fi

version=$1
builder=$2

# the tag is v$version
if ! echo "${version}" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+$' ; then
  echo "VERSION should be X.Y.Z (without the v)"
  exit 2
fi

case $builder in
  docker|podman)
  ;;
  *)
  echo "You should use either docker or podman for building"
  exit 3
esac

if ! grep -q "^### ${version} " CHANGES.md ; then
  echo "CHANGES.md has no entry for ${version}"
  exit 4
fi

if [ -n "`git status --porcelain`" ] ; then
  echo "The local repository is not clean"
  exit 5
fi

# the name given to register in config.ml names dist/$name.xen and the hashsums
name=`sed -n 's/.*register "\([^"]*\)".*/\1/p' config.ml | head -n 1`
if [ -z "$name" ] ; then
  echo "No unikernel name found in config.ml"
  exit 6
fi

echo "Building the unikernel ${version} with $builder."
./build-with.sh $builder

# CI and users check the first two, qubes-builderv2 wants a bare hash
echo "Updating hashsums and version files."
sha256sum dist/${name}.xen > ${name}.sha256
cp ${name}.sha256 ${name}-release.sha256
echo ${version} > version
echo 1 > rel
cut -d' ' -f1 ${name}.sha256 > rpm_spec/qubes-dnshole-${version}.xen.sha2

echo "Committing and tagging v${version}."
git add ${name}.sha256 ${name}-release.sha256 version rel rpm_spec/${name}-${version}.xen.sha256
git commit -m "release ${version}"
git tag v${version}

echo "SHA2 of release:"
cat ${name}-release.sha256
echo "Push the tag, then upload ./dist/${name}.xen and ${name}-release.sha256 to the v${version} release"
