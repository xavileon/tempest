#!/bin/bash

# Prepare the tempest working
# Pre-requisities:
# - execute this script from the base directory of tempest
# Steps:
# - Override the run_tempest.sh with our tunned script
# - Link to various utilities present in $MIDO_DIR/utilities except self


function usage {
    echo "Usage: $0 [OPTION]"
    echo "  -t  Tagged commit in tempest_tags file"
    echo "      if no tag exists, then it will take the argument as a commit revision (default: master)"
    echo "  -c  tempest.conf file with deployment info to modify to our midonet environment (default: etc/tempest.conf)"
    echo "  -d  Only clean the environment, ignores -t and -c options"
    echo "  -h  Help"
    exit 1
}

# DEFAULTS
MIDO_UTILS=midokura/utils
TAG_REV=master
CONFIG_FILE=etc/tempest.conf

if [ $# -eq 0 ]; then
   echo "WARNING: using defaults..."
   echo "-t master -c etc/tempest.conf"
   echo
fi


while getopts t:c:dh FLAG; do
    case $FLAG in
        t)
            TAG_REV=$OPTARG
            ;;
        c)
            CONFIG_FILE=$OPTARG
            ;;
        d)
            DELETE=1
            ;;
        h|?) 
            usage
            ;;
    esac
done

# VARIOUS CHECKS
# Check if we're working on the correct base dir
ls -lda $MIDO_UTILS/prepare_tempest.sh > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: you should execute this script from the top of the working tree."
    exit 1
fi

# Clean current workspace
shopt -s extglob
rm -rf !(.git|.venv|.testrepository|midokura) > /dev/null 2>&1

if [ $DELETE ]; then
    exit 0
fi

# Clone and checkout a specific tempest_revision
REVISION=$(cat $MIDO_UTILS/tempest_releases | grep $TAG_REV | awk '{print $2}')
# If no tag found, treat the TAG_REV as a revision
if [ -z $REVISION ]; then
    REVISION=$TAG_REV
fi
git clone https://github.com/openstack/tempest .tempest.tmp
cd .tempest.tmp
git cat-file -t $REVISION > /dev/null 2>&1
if [ $? -ne 0 ]; then
    echo "ERROR: revision $REVISION does not exist on tempest history"
    rm -rf .tempest.tmp
    exit 1
fi
git archive $REVISION | tar -x -C ../
cd ..
rm -rf .tempest.tmp
echo $TAG_REV $REVISION > .tempest_revision

# Link to various utilities of our own
ln -sf $MIDO_UTILS/run_tempest.sh run_tempest.sh
ln -sf $MIDO_UTILS/run_mido.sh run_mido.sh
ln -sf $MIDO_UTILS/run_clean_failed_tests.sh
ln -sf $MIDO_UTILS/mido-setup.py mido-setup.py
ln -sf $MIDO_UTILS/.gitignore .gitignore

# Check if tempest.conf exists, uses etc/tempest.conf by default
if [ ! -e $CONFIG_FILE ]; then
    echo "ERROR: tempest config file $CONFIG_FILE does not exists."
    exit 1
fi

# Prepare the virtualenv environment for mido-setup.py
python tools/install_venv.py

cp $CONFIG_FILE etc/

echo "Executing mido-setup.py..."
tools/with_venv.sh python mido-setup.py
