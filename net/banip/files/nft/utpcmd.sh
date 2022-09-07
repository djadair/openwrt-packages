#!/bin/sh

# Run utpl with lock to serialize access.  Sadly busybox does not
# support -w or we could have a timeout.

# The lock is reuired to make sure nft commands do not get garbled
# but messing around with the PID file is specific to the existing
# /etc/init.d/banip trying to use it as a psuedo-lock.

# If the init script stopped messing about the PID bits could be
# safely removed.

LOCK=/var/run/utpcmd.lock
cmd=$(basename ${1})
PID=/var/run/${cmd%%\.*}.pid

utpl=$(command -v utpl)

arg=""
if [ "$#" -lt 2 ]; then
    echo "$0: command missing" >&2
    arg="start"
fi

(
    if flock -x 99; then
	# If someone else set our PID leave it alone
	[ ! -s $PID ] || echo $$ > ${PID}
	${utpl} -S $@ $arg
	# But always clear PID on exit.
	: > ${PID}
    else
	echo "$0: could not obtain lock\n"
	exit 2
    fi
    
) 99>${LOCK}
