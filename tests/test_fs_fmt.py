# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
import os
import logging.config
import logging
import sys
import inspect
import cmd


currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))

import settings

logging.config.dictConfig(settings.LOGGING)

log = logging.getLogger('main')
ch = logging.StreamHandler()
ch.setLevel(logging.DEBUG)
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
ch.setFormatter(formatter)
log.addHandler(ch)


BS = 512
CDISK_MNT_DIR = '/tmp/cdisk_dir'
USER = 'andrey'
FS_TYPE = 'ext4'
DISK_NUM = 1
CDISK_DEV = '/dev/cdisk'

def test():
    try:
        disk_num = DISK_NUM
        cmd.exec_cmd2('insmod ' + settings.CD_CLI_MOD_KO_P, throw = True)
        cmd.exec_cmd2(settings.CD_CLI_CTL_P + ' --create ' + str(disk_num), throw = True)
        cmd.exec_cmd2('dd if=/dev/zero of=' + CDISK_DEV + ' bs=' + str(BS) + ' count=' + str(settings.CD_SIZE//BS), throw = True)
        cmd.exec_cmd2('/sbin/mkfs -t ' + FS_TYPE + ' ' +  CDISK_DEV + str(disk_num))
        cmd.exec_cmd2('rm -r -f ' + CDISK_MNT_DIR)
        cmd.exec_cmd2('mkdir ' + CDISK_MNT_DIR, throw = True)
        cmd.exec_cmd2('mount -t ' + FS_TYPE + ' ' + CDISK_DEV + str(disk_num) + ' ' + CDISK_MNT_DIR)
        cmd.exec_cmd2('dd if=/dev/zero of=' + os.path.join(CDISK_MNT_DIR, 'random.txt') + ' bs=' + str(BS) + ' count=1000')
        cmd.exec_cmd2('du -ah ' + CDISK_MNT_DIR)
        cmd.exec_cmd2('umount ' + CDISK_MNT_DIR)
        cmd.exec_cmd2(settings.CD_CLI_CTL_P + ' --delete ' + str(disk_num), throw = True)
    except Exception as e:
        log.exception(str(e))
    finally:
        try:
            cmd.exec_cmd2('rmmod ' + settings.CD_CLI_MOD, throw = True)
        except Exception as e:
            log.exception(str(e))

if __name__=="__main__":
    test()


