#!/bin/bash

# Prepare the tempest working
# Pre-requisities:
# - execute this script from the base directory of tempest
# Steps:
# - Override the run_tempest.sh with our tunned script
# - Link to various utilities present in $MIDO_DIR/utilities except self

MIDO_DIR=tempest/scenario/midokura

rm -rf run_tempest.sh

for UTILITY in $(ls -I ${0##*/} $MIDO_DIR/utilities); do
    echo ln -s $MIDO_DIR/utilities/$UTILITY $UTILITY
done
