#!/bin/bash

if [ -n "$(git diff-index HEAD --)" ]; then
	echo "WARNING - uncommitted changes!  Please commit work before packaging"
	exit 1
fi

# Get the last committed version, (if it was the last commit)
VERSION="$(git tag --points-at HEAD)"
if [ -z "$VERSION" ]; then
	# If last commit was not a tag, get the ID of the last commit
	VERSION="$(date +%Y%m%d)-$(git rev-parse HEAD)"
fi

python3 -m venv venv
source venv/bin/activate
python3 -m pip install --upgrade pip
pip3 install -e .[dev]

flake8 src/
if [ "$?" -ne 0 ]; then
	echo "ERROR - flake8 failed"
	exit 1
fi

pyinstaller -F src/net_diag/network_discover.py
cp README.md LICENSE.md dist/
tar -czf "build/net_diag-$(uname -s | tr '[:upper:]' '[:lower:]')-$(uname -m)-$VERSION.tgz" -C dist network_discover README.md LICENSE.md