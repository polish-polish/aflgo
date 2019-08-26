#!/bin/bash
sed -n '1~2p' $1 |awk -F " " '{print $3}'|sed  "s/elapsed//g"

