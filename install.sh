#!/bin/bash
# (c) J~Net 2024
#
# ./install.sh
#
function x(){
sudo chmod +x $1
}

echo "Installing..."

sudo cp ./duplicate-remover /usr/local/bin/
x /usr/local/bin/duplicate-remover
