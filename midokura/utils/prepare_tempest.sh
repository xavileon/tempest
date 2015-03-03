#!/bin/bash

# Prepare the tempest working
# Pre-requisities:
# - execute this script from the base directory of tempest
# Steps:
# - Override the run_tempest.sh with our tunned script
# - Link to various utilities present in $MIDO_DIR/utilities except self

MIDO_UTILS=midokura/utils

if [ $# -ne 1 ]; then
    echo "Usage: $MIDO_UTILS/prepare_tempest.sh [-d | tempest_revision]"
    echo "if -d is passed, it will only clean the environment"
    exit 1
fi

# Check if we're working on the correct base dir
ls -lda $MIDO_UTILS/prepare_tempest.sh > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: you should execute this script from the top of the working tree"
    exit 1
fi

# Clean current workspace
shopt -s extglob
rm -rf !(.git|midokura) > /dev/null 2>&1

if [ $1 = "-d" ]; then
    exit 0
fi

# Clone and checkout a specific tempest_revision
git clone https://github.com/openstack/tempest .tempest.tmp
cd .tempest.tmp
git cat-file -t $1 > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: revision $1 does not exist on tempest history"
    rm -rf .tempest.tmp
    exit 1
fi
git archive $1 | tar -x -C ../
cd ..
rm -rf .tempest.tmp
echo $1 > .tempest_revision

# Link to various utilities of our own
ln -sf $MIDO_UTILS/run_tempest.sh run_tempest.sh
ln -sf $MIDO_UTILS/run_mido.sh run_mido.sh
ln -sf $MIDO_UTILS/run_clean_failed_tests.sh
ln -sf $MIDO_UTILS/mido-setup.py mido-setup.py
ln -sf $MIDO_UTILS/.gitignore .gitignore

echo "Done!"
echo "Remember to:"
echo " - copy tempest.conf to etc"
echo " - python mido-setup.py"
