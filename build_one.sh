#!/bin/sh
set -x
make ${1}.so; cp ${1}.so cap.so
