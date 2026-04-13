set pagination off
set confirm off
printf "MARKER=%u\n", procdump_test_marker
printf "SHAREDLIBS_START\n"
info shared
printf "SHAREDLIBS_END\n"
quit
