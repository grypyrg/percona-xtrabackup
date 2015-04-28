################################################################################
# Bug 1277403: Use FLUSH TABLES before FTWRL                                   #
################################################################################

start_server

has_backup_locks && skip_test "Requires server without backup locks support"

$MYSQL $MYSQL_ARGS -Ns -e \
       "SHOW GLOBAL STATUS LIKE 'Com_%lock%'; \
       SHOW GLOBAL STATUS LIKE 'Com_flush%'" \
       > $topdir/status1

diff $topdir/status1 - <<EOF
Com_lock_tables	0
Com_unlock_tables	0
Com_flush	0
EOF

innobackupex --no-timestamp $topdir/full_backup

$MYSQL $MYSQL_ARGS -Ns -e \
       "SHOW GLOBAL STATUS LIKE 'Com_%lock%'; \
       SHOW GLOBAL STATUS LIKE 'Com_flush%'" \
       > $topdir/status2

diff $topdir/status2 - <<EOF
Com_lock_tables	0
Com_unlock_tables	1
Com_flush	3
EOF
