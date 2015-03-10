################################################################################
# Test xbcloud
#
# Set following environment variables to enable this test:
#     SWIFT_URL, SWIFT_USER, SWIFT_KEY, SWIFT_CONTAINER
#
################################################################################

. inc/common.sh

[ "${SWIFT_URL:-unset}" == "unset" ] && skip_test "Requires Swift"

SWIFT_ARGS="--swift-user=${SWIFT_USER} \
--swift-url=${SWIFT_URL} \
--swift-key=${SWIFT_KEY} \
--storage=SWIFT"

start_server --innodb_file_per_table

load_dbase_schema sakila
load_dbase_data sakila

full_backup_dir=$topdir/full_backup
part_backup_dir=$topdir/part_backup

vlog "take full backup"

innobackupex --stream=xbstream $full_backup_dir \
	--extra-lsndir=$full_backup_dir | xbcloud put \
	--swift-container=test_backup \
	${SWIFT_ARGS} \
	--parallel=10 \
	full_backup

vlog "take incremental backup"

inc_lsn=`grep to_lsn $full_backup_dir/xtrabackup_checkpoints | \
             sed 's/to_lsn = //'`

[ -z "$inc_lsn" ] && die "Couldn't read to_lsn from xtrabackup_checkpoints"

innobackupex --incremental --incremental-lsn=$inc_lsn \
	--stream=xbstream part_backup_dir | xbcloud put \
	--swift-container=test_backup \
	${SWIFT_ARGS} \
	incremental

vlog "download and prepare"

mkdir $topdir/downloaded_full
mkdir $topdir/downloaded_inc

xbcloud get --swift-container=test_backup \
	${SWIFT_ARGS} \
	full_backup | xbstream -xv -C $topdir/downloaded_full

innobackupex --apply-log --redo-only $topdir/downloaded_full

xbcloud get --swift-container=test_backup \
	${SWIFT_ARGS} \
	incremental | xbstream -xv -C $topdir/downloaded_inc

innobackupex --apply-log --redo-only $topdir/downloaded_full \
	--incremental-dir=$topdir/downloaded_inc

innobackupex --apply-log $topdir/downloaded_full

# test partial download

mkdir $topdir/partial

xbcloud get --swift-container=test_backup ${SWIFT_ARGS} full_backup \
	ibdata1 sakila/payment.ibd > $topdir/partial/partial.xbs

xbstream -xv -C $topdir/partial < $topdir/partial/partial.xbs \
				2>$topdir/partial/partial.list

diff -u $topdir/partial/partial.list - <<EOF
ibdata1
sakila/payment.ibd
EOF
