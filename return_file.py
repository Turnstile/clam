from db_ops import return_file, approve_queue
import argparse, configparser
import syslog
from pathlib import Path
import requests, json

parser = argparse.ArgumentParser()
config = configparser.ConfigParser()
config.read('config.ini')
token = config['Default']['X-Auth-Token']
local_db = config['Default']['Local Database']
credentials = config['Default']['Credential File']
parser.add_argument('file', nargs='?', default='', help='Name of file to be restored')
filepath = parser.parse_args().file

syslog.openlog(ident="clamscan", logoption=syslog.LOG_PID)

return_file(local_db, credentials, filepath)
approve_queue(token, local_db)
	
syslog.closelog()

