#!/bin/bash

#echo -n "[+] Downloading oui.txt from ieee.org... "
#curl http://standards-oui.ieee.org/oui.txt -s -o oui.txt
#if [ $? -eq 0 ]; then
#    echo "Success"
#else
#    echo "Failure. Exiting."
#    exit 1
#fi

echo -n "[+] Building oui.h. This may take a few minutes... "

# Place header at the top of the file
cat << EOF >oui.h
/* oui.h -- updated with more current OUI list from IEEE:
 *       -- http://standards-oui.ieee.org/oui.txt
 *
 * Code indentation/formatting from the original was also changed.
 */

/*
 *  \$Id: oui.h,v 1.1.1.1 2001/11/29 00:16:48 route Exp \$
 *
 *  Building Open Source Network Security Tools
 *  oui.h - pcap example code
 *
 *  Copyright (c) 2002 Mike D. Schiffman <mike@infonexus.com>
 *  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS \`\`AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */


struct oui {
  u_char prefix[3];
  char *vendor;
};

struct oui oui_table[] = {
EOF

# Sort oui.txt and create oui_table entries
while read -r line
do
    oui=$(echo "$line" | awk '{print $1}')
    octet1=$(echo "$oui" | cut -d - -f 1)
    octet2=$(echo "$oui" | cut -d - -f 2)
    octet3=$(echo "$oui" | cut -d - -f 3)

    vendor=$(echo -n "$line" | awk '{$1=""; $2=""; print}' | sed 's/^ *//g')

    #  { { 0x84, 0x27, 0xCE }, "Corporation of the Presiding Bishop of The Church of Jesus Christ of Latter-day Saints" },
    echo "  { { 0x${octet1}, 0x${octet2}, 0x${octet3}, }, \"${vendor}\" }," >>oui.h
done < <(grep "(hex)" oui.txt | sort | tr -d '\015')

# Footer

echo "  { { 0x00, 0x00, 0x00 }, \"\" }" >>oui.h
echo "};" >>oui.h

echo "Done."

