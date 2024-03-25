#!/bin/bash
# Find the operating system profile in the memory image
# "--profile=Win10x64_15063
# Save the intialisation files to the project folder provided as an argument to autovol3.py
# If the required files exist, don't run this script

# If the project folder is not exist, create one

# Display usage message

usage() {
    echo "Usage: $0 <memory dump> <project path>"
    exit 1
}

if [ $# -ne 2 ]; then
    usage
fi

image_hash=$(sha256sum $1)

if [ ! -d "$2" ]; then
    mkdir -p "$2"       # Create folder if it does not exist
    echo "Project folder '$2' created."

    # Create a txt file and write the hash value of the image file
    echo "$image_hash" > $2/image_signature
else
    echo "Project folder '$2' already exist."

    # Check if there is a hash value for the image in the project folder. 
    # If there is, compare with the hash value provided by the user
    signature="$2/image_signature"


    if [ -e "$signature" ]; then

        old_image_hash=$(cat $signature)

        if [[ "$image_hash" == "$old_image_hash" ]]; then
            echo "This image have been analyzed before, do you want to continue with it"

        else
            echo "This is a new image"

        fi
    else
        echo "Writing image ssignature to image_signature"
        echo "$image_hash" > "$signature"

    fi

    exit 1

fi
# Run Volatility plugins to initialize required files for processing

echo "Initializing pslist ..."
vol  -r csv -f $1 windows.pslist > $2/pslist.csv

echo "Initializing psscan ..."
vol  -r csv -f $1 windows.psscan > $2/psscan.csv

