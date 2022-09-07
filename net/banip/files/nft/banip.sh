#!/bin/sh
# Both Luci and banip init script expect /usr/bin/banip.sh
# so give them one.  A soft-link would work too but that is
# trickier to install.

# wierdness from procd -- no args means start.
if [ "0" -lt "$#" ] ; then
    cmd="$@"
else
    cmd="start"
fi

t=$(pwd)
cd /usr/share/banip
./banip.uc $cmd 2>/dev/null
cd $t

