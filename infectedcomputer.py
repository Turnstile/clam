import subprocess 
import argparse
import configparser
from pathlib import Path
import datetime
import shlex
import sqlite3
import syslog
import uuid
from datetime import datetime
from computer import Computer
from db_ops import sha256sum

class InfectedComputer(Computer):
	
	def __init__(self, db, quarantine, log_file, quarantine_db, comp_path, credentials, mount_point="/mnt/infected"):
		"""Constructor for infected_computer class
		
		:param db: the location of the virus database
		:param quarantine: the location of the quarantine directory
		:param log_file: the location (temporarily) to put the clamscan log file that is generated
		:param comp_path: the path of the parent directory of the virus, in the form of //COMPUTERNAME/DRIVELETTER$/PATH
		:param quarantine_db: the location of the quarantine database
		:param credentials: the location of the credential file used to mount filesystems
		:param mount_point: where the comp_path is to be mounted locally
		"""
		self.db = db
		self.quarantine = quarantine
		self.log_file = log_file	
		self.quarantine_db = quarantine_db
		super(InfectedComputer, self).__init__(comp_path, credentials, mount_point)
		self.virus_list = []
		self.quarantine_list = []
			
	def scan(self):
		"""Scan mounted drive using the virus database and quarantine any detections"""
		#if quarantine dir does not exist, create one
		if not Path(self.quarantine).is_dir():
			syslog.syslog(syslog.LOG_NOTICE, "No quarantine directory found, creating new one at " + self.quarantine)
			Path(self.quarantine).mkdir(mode=0o664, parents=True)		

		#run scan using carbon black virus database
		syslog.syslog(syslog.LOG_NOTICE, "Running scan of " + self.mount_point)
		cmd = "clamscan --quiet --no-summary " + self.mount_point + " --exclude " + self.quarantine + " -il " + self.log_file + " -d " + self.db + " --move " + self.quarantine 
		subprocess.run(shlex.split(cmd))
	
	def log_detections(self):
		"""Read clamAV generated log file and put any detections in a list"""
		#find infected files from scan (if any)
		p = Path(self.log_file)
		if p.exists():
			with p.open() as f:
				for line in f:
					if 'moved to' in line:
						s = line.split(': moved to', 1) 
						file_name = Path(s[0].strip()).name
						source = self.comp_path + '/' + file_name
						dest = s[1].replace("'", "").strip() 
						self.virus_list.append((source, dest))				
			f.close()	
		
		#remove log file
		p.unlink()

	def rename_quarantine(self):
		"""Add .quarantine to extension"""
		for virus in self.virus_list:				
			source, dest = virus[0], virus[1]
			#uniquely name files with .quarantine extension
			q = Path(dest)
			new_dest = str(q) + '.quarantine' 
			q.rename(new_dest)
			#log virus detection to syslog
			syslog.syslog(syslog.LOG_ALERT, 'VIRUS DETECTED: ' + source + ' moved to ' + new_dest)
			#append to list of quarantined viruses
			self.quarantine_list.append((new_dest, source, datetime.now()))
									
	def leave_txt(self):			
		"""Leave a .txt file in place of the quarantined file"""
		for virus in self.virus_list:
			source = virus[0]	
			#leave note in place of quarantined file
			dest = Path(source).with_suffix(".txt")
			text = self.mount_point + '/' + dest.name 
			syslog.syslog(syslog.LOG_NOTICE, "Leaving contact information at " + str(dest))
			with open(text, 'w') as o:
				o.write(source + " has been identified as a virus and moved to quarantine. If you believe this to be an error please contact the helpdesk at ITS.HelpDesk@traviscountytx.gov\n")
			o.close()
		
	def write_to_quarantine_db(self):
		"""Add detected virsuses to the quarantine database"""
		syslog.syslog(syslog.LOG_NOTICE, "Adding quarantined viruses to quarantine database")
		conn = sqlite3.connect(self.quarantine_db)
		c = conn.cursor()
		c.executemany('REPLACE INTO quarantine VALUES (?,?,?)', self.quarantine_list)
		conn.commit()
		c.close()
		conn.close()
			
