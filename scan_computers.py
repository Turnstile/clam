import configparser
import argparse
import syslog
from pathlib import PureWindowsPath, Path
from infectedcomputer import InfectedComputer
from db_ops import build_virus_db, build_quarantine_db
from computer import Computer
import sys

#defaults from config
config = configparser.ConfigParser()
config.read('config.ini')
virus_db = config['Default']['Virus Database']
token = config['Default']['X-Auth-Token']
quarantine = config['Default']['Quarantine']
log_file = config['Default']['Log File']
default_scan = config['Default']['Home Directory']
quarantine_db = config['Default']['Quarantine Database']
credentials = config['Default']['Credential File']

#pars arguments if supplied
parser = argparse.ArgumentParser()
parser.add_argument('-s', const='86400', default='86400', nargs='?', help='Seconds since last chron job')
seconds = parser.parse_args().s

syslog.openlog(ident='clamscan', logoption=syslog.LOG_PID)
infected_df = build_virus_db(token, virus_db, seconds)
#TODO for testing only, remove
#print("Infected Files: ")
#print(infected_df)

#if no quarantine database exists, create one
if not Path(quarantine_db).exists():
	build_quarantine_db(quarantine_db)

#create list of paths to be mounted
paths = []
for index, row in infected_df.iterrows():
	comp = PureWindowsPath(row['computerId_name']).stem
	local_path = PureWindowsPath(row['pathName'])
	path = '//' + comp + '/' + local_path.as_posix().replace(":", "$")
	#TODO for testing only, remove
	#print("Paths to be scanned: " + path)
	paths.append(path) 

#TODO For testing only, remove
#paths = ['//ITS-172099/c$/users/BradshJ1/desktop', '//ITS-172099/c$/users/BradshJ1/pictures/test']

#mount paths and run scan
for path in paths:
	try:
		comp = InfectedComputer(virus_db, quarantine, log_file, quarantine_db, path, credentials)
		comp.mount()
	except exception(e):
		print(e)
		syslog.syslog(syslog.LOG_ALERT, "Failed to mount " + path + ", exiting program")
		sys.exit()
	comp.scan()
	comp.log_detections()
	#if no viruses were found, write to log and continue on next iteration
	if not comp.virus_list:
		syslog.syslog(syslog.LOG_ALERT, "No viruses found during scan of " + path)
		comp.unmount()
		continue
	#TODO for testing only, remove
	#print("Virus List: ")
	#print(comp.virus_list)
	comp.rename_quarantine()
	#TODO for testing only, remove
	#print("Quarantine List: ")
	#print(comp.quarantine_list)
	comp.leave_txt()
	comp.write_to_quarantine_db()
	comp.unmount()	

syslog.closelog()
