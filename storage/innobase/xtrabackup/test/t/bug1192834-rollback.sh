##########################################################################
# Bug 1192834: Crash during apply with index compaction enabled          #
##########################################################################

. inc/common.sh

start_server --innodb_file_per_table
load_dbase_schema sakila
load_dbase_data sakila

function start_uncomitted_transaction()
{
    run_cmd $MYSQL $MYSQL_ARGS sakila <<EOF
START TRANSACTION;
DELETE FROM payment;
SELECT SLEEP(10000);
EOF
}

start_uncomitted_transaction &
job_master=$!

sleep 2

backup_dir="$topdir/backup"

innobackupex --no-timestamp --compact $backup_dir
vlog "Backup created in directory $backup_dir"

kill -SIGKILL $job_master
stop_server

# Remove datadir
rm -r $mysql_datadir

# Restore sakila

innobackupex --apply-log --rebuild-indexes $backup_dir

vlog "Restoring MySQL datadir"
mkdir -p $mysql_datadir
innobackupex --copy-back $backup_dir

start_server
