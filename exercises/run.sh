#!/bin/sh

set -eux

d=$1

cd $d
npm install
cd ..
cp node_module/nosql/index.js $d/node_modules/nosql/index.js
