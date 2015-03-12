###############################################################################
# Bug #1190335: Stream decryption fails with options in my.cnf
###############################################################################

MYSQLD_EXTRA_MY_CNF_OPTS="
loose-encrypt=AES256
loose-encrypt-key=6F3AD9F428143F133FD7D50D77D91EA4
"

start_server

cat ${MYSQLD_VARDIR}/my.cnf

# both must succeed
set -o pipefail

innobackupex --stream=xbstream $topdir/tmp | \
	xbcrypt -d --encrypt-algo=AES256 \
	--encrypt-key=6F3AD9F428143F133FD7D50D77D91EA4 >/dev/null

set -o pipefail
