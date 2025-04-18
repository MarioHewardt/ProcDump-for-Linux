#!/bin/bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )";
OS=$(uname -s)
if [ "$OS" = "Darwin" ]; then
    runProcDumpAndValidate=$DIR/../runProcDumpAndValidate.sh;
else
    runProcDumpAndValidate=$(readlink -m "$DIR/../runProcDumpAndValidate.sh");    
fi

source $runProcDumpAndValidate

TESTPROGNAME="ProcDumpTestApplication"
TESTPROGMODE="tc"

# TARGETVALUE is only used for stress-ng
#TARGETVALUE=3M

# These are all the ProcDump switches preceeding the PID
PREFIX="-tc 50"

# This are all the ProcDump switches after the PID
POSTFIX=""

# Indicates whether the test should result in a dump or not
SHOULDDUMP=true

# Only applicable to stress-ng and can be either MEM or CPU
RESTYPE=""

# The dump target
DUMPTARGET=""

runProcDumpAndValidate