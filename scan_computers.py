import configparser
import argparse
import syslog
from pathlib import PureWindowsPath, Path
from infectedcomputer import InfectedComputer
from db_ops import *
from computer import Computer
import sys

#defaults from config
config = configparser.ConfigParser()
config.read('config.ini')
virus_db = config['Default']['Virus Database']
token = config['Default']['X-Auth-Token']
quarantine = config['Default']['Quarantine']
log_file = config['Default']['Log File']
credentials = config['Default']['Credential File']
local_db = config['Default']['Local Database']

#parse arguments if supplied
parser = argparse.ArgumentParser()
parser.add_argument('-s', const='86400', default='86400', nargs='?', help='Seconds since last chron job')
seconds = parser.parse_args().s

syslog.openlog(ident='clamscan', logoption=syslog.LOG_PID)

#if no quarantine database exists, create one
if not Path(local_db).exists():
	build_local_db(local_db)

#build virus signature database
infected_df = build_virus_db(token, virus_db, local_db, seconds)
#TODO for testing only, remove
#print("Infected Files: ")
#print(infected_df)

#create list of paths to be mounted
paths = []
for index, row in infected_df.iterrows():
	comp = PureWindowsPath(row['computerId_name']).stem
	local_path = PureWindowsPath(row['pathName'])
	path = '//' + comp + '/' + local_path.as_posix().replace(":", "$")
	paths.append((path, comp)) 

#TODO for testing only, remove
#print(paths)
#paths = []

#TODO For testing only, remove
#paths = [("//ITS-172099/c$/users/BradshJ1/desktop", "ITS-172099"), ('//ITS-172099/c$/users/BradshJ1/pictures/test', "ITS-172099")]

#mount paths and run scan
for path in paths:
	try:
		#make sub directory for each computer 
		sub_quarantine = quarantine + '/' + path[1]
		comp = InfectedComputer(virus_db, sub_quarantine, log_file, local_db, path[0], credentials)
		comp.mount()
	except Exception as e:
		print(e)
		syslog.syslog(syslog.LOG_ALERT, "Failed to mount " + path[0])
		continue		
	comp.scan()
	comp.log_detections()
	#if no viruses were found, write to log and continue on next iteration
	if not comp.virus_list:
		syslog.syslog(syslog.LOG_ALERT, "No viruses found during scan of " + path[0])
		comp.unmount()
		continue
	#TODO for testing only, remove
	#print("Virus List: ")
	#print(comp.virus_list)
	comp.rename_quarantine()
	comp.leave_txt()
	comp.write_to_quarantine_db()
	comp.unmount()	

#attempt to clear approval queue
approve_queue(token, local_db)

syslog.closelog()
