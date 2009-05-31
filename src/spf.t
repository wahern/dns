#!/bin/sh

SPF=./spf
VERBOSE=
ERRBUF=/dev/null


rand() {
	dd if=/dev/urandom bs=1 count=4 2>/dev/null | od -t u4 | awk 'NR=1{print $2}'
} # rand


say() {
	printf "$@"
} # say


check() {
	if [ $1 -eq 0 ]; then
		say "OK "
		shift 1
		say "$@"
	else
		say "FAIL "
		shift 1
		say "$@"

		cat $ERRBUF >&2

		exit 1
	fi
} # check


parse() {
	$SPF $VERBOSE parse "$1" 2>|$ERRBUF

	check $? "parse \`%s'\n" "$1"
} # parse


usage() {
	cat <<-EOF
		spf.t -vh
		  -p  PATH  Path to spf utility
		  -v        Be verbose
		  -h        Print usage

		Report bugs to william@25thandClement.com
	EOF
} # usage

while getopts p:vh OPT; do
	case $OPT in
	p)
		SPF="$OPTARG"
		;;
	v)
		VERBOSE='-v'
		;;
	h)
		usage >&2
		exit 0;
		;;
	?)
		usage >&2
		exit 1;
		;;
	esac
done

shift $(($OPTIND - 1))


#
# Setup secure error buffer
#
TMPDIR=${TMPDIR:-/tmp}
TMPDIR=${TMPDIR%/}

ERRBUF="${TMPDIR}/.spf.t.$(rand)"

if [ "${ERRBUF}" == "${TMPDIR}/.spf.t." ]; then
	printf "$0: unable to divert stderr\n"

	if [ -a /dev/stderr ]; then
		ERRBUF=/dev/stderr
	else
		ERRBUF=/dev/null
	fi
else
	trap "rm ${ERRBUF}" 0
fi


#
# RFC 4408 16.1 B.1. Simple Examples
#
parse 'v=spf1 +all'
parse 'v=spf1 a -all'
parse 'v=spf1 a:example.org -all'
parse 'v=spf1 mx -all'
parse 'v=spf1 mx:example.org -all'
parse 'v=spf1 mx mx:example.org -all'
parse 'v=spf1 mx/30 mx:example.org/30 -all'
parse 'v=spf1 ptr -all'
parse 'v=spf1 ip4:192.0.2.128/28 -all'


#
# Phew!
#
say "GOOD JOB!!!\n"

exit 0

