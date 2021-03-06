# vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
import os
import inspect

currentdir = os.path.dirname(os.path.abspath(inspect.getfile(inspect.currentframe())))
CURR_DIR = os.path.abspath(currentdir)
PROJ_DIR = os.path.dirname(CURR_DIR)

BIN_DIR = os.path.join(PROJ_DIR, "bin")

CD_CLI_MOD = 'cd_cli'
CD_CLI_MOD_KO = CD_CLI_MOD + '.ko'
CD_CLI_CTL = 'cd_cli_ctl'

CD_CLI_MOD_KO_P = os.path.join(BIN_DIR, CD_CLI_MOD_KO)
CD_CLI_CTL_P = os.path.join(BIN_DIR, CD_CLI_CTL)
CD_BLOCK_SIZE = 64*1024
CD_BLOCKS = 1000

CD_SIZE = CD_BLOCKS*CD_BLOCK_SIZE

LOGGING = {
    'version' : 1,
    'disable_existing_loggers' : False,
    'formatters': {
        'verbose' : {
            'format' : '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple' : {
            'format' : '%(levelname)s %(asctime)s %(module)s %(message)s'
        },
    },
    'handlers' : {
	'file' : {
            'level' : 'DEBUG',
	    'class' : 'logging.FileHandler',
            'formatter' : 'simple',
            'filename' : os.path.join(CURR_DIR, 'tests.debug.log'),
	},
    },
    'loggers' : {
        'django.request' : {
            'handlers' : ['file'],
            'level' : 'DEBUG',
            'propagate' : True,
        },
        'main' : {
            'handlers' : ['file'],
            'level' : 'DEBUG',
            'propagate' : True,
        },
    },
}

