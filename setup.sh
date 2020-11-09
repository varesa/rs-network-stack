#!/bin/Sh

sudo brctl addbr rs-test-br
sudo ip a a 169.254.0.1/24 dev rs-test-br
sudo ip l set rs-test-br up

