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



def test():
    try:
        cmd.exec_cmd2('insmod ' + settings.CDISK_MOD_KO_P, throw = True)
        cmd.exec_cmd2(settings.CDISK_CTL_P + ' --create', throw = True)
        cmd.exec_cmd2('dd if=/dev/zero of=/dev/cdisk1 bs=512', throw = True)  
    except Exception as e:
        log.exception(str(e))
    finally:
        try:
            cmd.exec_cmd2('rmmod ' + settings.CDISK_MOD)
        except Exception as e:
            log.exception(str(e))

if __name__=="__main__":
    test()


