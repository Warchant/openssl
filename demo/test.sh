#!/bin/bash
set -o verbose

#  ┌─┐┌─┐┌┬┐┬ ┬  ┌┬┐┌─┐  ┌┐ ┌─┐┌─┐┬┌─┌┬┐┌─┐┌─┐┬─┐┌─┐┌┬┐  ┌─┐┌─┐┌─┐┌┐┌┌─┐┌─┐┬  
#  ├─┘├─┤ │ ├─┤   │ │ │  ├┴┐├─┤│  ├┴┐ │││ ││ │├┬┘├┤  ││  │ │├─┘├┤ │││└─┐└─┐│  
#  ┴  ┴ ┴ ┴ ┴ ┴   ┴ └─┘  └─┘┴ ┴└─┘┴ ┴─┴┘└─┘└─┘┴└─└─┘─┴┘  └─┘┴  └─┘┘└┘└─┘└─┘┴─┘
BUILD_PATH=/home/bogdan/tools/openssl/build
LD_LIBRARY_PATH=$BUILD_PATH
OSSL=$BUILD_PATH/apps/openssl
read

#  ┌─┐┌┐┌┌─┐┬─┐┌─┐┌┬┐┌─┐  ┌┬┐┬ ┬┌─┐  ┬  ┬┬ ┬┬  ┌┐┌┌─┐┬─┐┌─┐┌┐ ┬  ┌─┐  ╔═╗╔═╗  ┌─┐┬─┐┬┬  ┬┌─┐┌┬┐┌─┐  ┬┌─┌─┐┬ ┬┌─┐
#  ├┤ │││├┤ ├┬┘├─┤ │ ├┤    │ ││││ │  └┐┌┘│ ││  │││├┤ ├┬┘├─┤├┴┐│  ├┤   ║╣ ║    ├─┘├┬┘│└┐┌┘├─┤ │ ├┤   ├┴┐├┤ └┬┘└─┐
#  └─┘┘└┘└─┘┴└─┴ ┴ ┴ └─┘   ┴ └┴┘└─┘   └┘ └─┘┴─┘┘└┘└─┘┴└─┴ ┴└─┘┴─┘└─┘  ╚═╝╚═╝  ┴  ┴└─┴ └┘ ┴ ┴ ┴ └─┘  ┴ ┴└─┘ ┴ └─┘
$OSSL ecparam -genkey -name secp256k1 -out /tmp/vuln1.pem || exit 1
$OSSL ecparam -genkey -name secp256k1 -out /tmp/vuln2.pem || exit 1
read

#  ┬┌─┌─┐┬ ┬  ┌┬┐┌─┐┌┬┐┌─┐┬┬  ┌─┐
#  ├┴┐├┤ └┬┘   ││├┤  │ ├─┤││  └─┐
#  ┴ ┴└─┘ ┴   ─┴┘└─┘ ┴ ┴ ┴┴┴─┘└─┘
$OSSL ec -text -in /tmp/vuln1.pem && read
$OSSL ec -text -in /tmp/vuln2.pem && read

#  ┌─┐┌─┐┌┐┌┌─┐┬─┐┌─┐┌┬┐┌─┐  ┌─┐┬ ┬┌┐ ┬  ┬┌─┐  ┬┌─┌─┐┬ ┬┌─┐
#  │ ┬├┤ │││├┤ ├┬┘├─┤ │ ├┤   ├─┘│ │├┴┐│  ││    ├┴┐├┤ └┬┘└─┐
#  └─┘└─┘┘└┘└─┘┴└─┴ ┴ ┴ └─┘  ┴  └─┘└─┘┴─┘┴└─┘  ┴ ┴└─┘ ┴ └─┘
$OSSL ec -in /tmp/vuln1.pem -pubout -out /tmp/pub-vuln1.pem -text || exit 1
$OSSL ec -in /tmp/vuln2.pem -pubout -out /tmp/pub-vuln2.pem -text || exit 1
read


#  ┌─┐─┐ ┬┌─┐┬  ┌─┐┬┌┬┐┬┌┐┌┌─┐  ┌┐ ┌─┐┌─┐┬┌─┌┬┐┌─┐┌─┐┬─┐
#  ├┤ ┌┴┬┘├─┘│  │ ││ │ │││││ ┬  ├┴┐├─┤│  ├┴┐ │││ ││ │├┬┘
#  └─┘┴ └─┴  ┴─┘└─┘┴ ┴ ┴┘└┘└─┘  └─┘┴ ┴└─┘┴ ┴─┴┘└─┘└─┘┴└─
$OSSL ec -hack -attacker attacker.pem -pkey1 /tmp/pub-vuln1.pem -pkey2 /tmp/pub-vuln2.pem || exit 1
read

#  ┌─┐┌─┐┌┬┐┌─┐┌─┐┬─┐┌─┐  ┬ ┬┬┌┬┐┬ ┬  ┌─┐┬─┐┬┌─┐┬┌┐┌┌─┐┬    ┌─┐┬─┐┬┬  ┬┌─┐┌┬┐┌─┐  ┬┌─┌─┐┬ ┬
#  │  │ ││││├─┘├─┤├┬┘├┤   ││││ │ ├─┤  │ │├┬┘││ ┬││││├─┤│    ├─┘├┬┘│└┐┌┘├─┤ │ ├┤   ├┴┐├┤ └┬┘
#  └─┘└─┘┴ ┴┴  ┴ ┴┴└─└─┘  └┴┘┴ ┴ ┴ ┴  └─┘┴└─┴└─┘┴┘└┘┴ ┴┴─┘  ┴  ┴└─┴ └┘ ┴ ┴ ┴ └─┘  ┴ ┴└─┘ ┴ 
$OSSL ec -in /tmp/vuln2.pem -text || exit 1
