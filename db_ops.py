from pathlib import Path, PureWindowsPath
import sqlite3
import requests, json
import pandas as pd
import datetime
import syslog
import urllib3
from computer import Computer
import sys
import shutil
import hashlib

def build_virus_db(token, virus_db, local_db, seconds):

	#disable insecure request warning
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

	#prepare request
	authJson = {
		'X-Auth-Token': token,
		'content-type': 'application/json'
		}

	url = 'https://cbep/api/bit9platform/v1/FileInstance'
	query = {'expand': ['fileCatalogId', 'computerId'], 'q': ['dateCreated>-' + seconds + 's', 'fileCatalogId_threat:50|100', 'localState!2']}
	b9StrongCert = False 

	syslog.syslog(syslog.LOG_NOTICE, 'Requesting virus database update since last scan, ' + seconds + ' seconds ago')

	#send request (equivalent to Clam AV Malware Export for potential threats)
	r = requests.get(url, params=query, headers=authJson, verify=b9StrongCert)
	potential_threats = r.json()
	
	#create dataframe of potential threats
	df = pd.DataFrame(potential_threats)
	
	if df.empty:
		syslog.syslog(syslog.LOG_NOTICE, "No potential viruses found in carbon black database, exiting program")
		sys.exit()	
	
	#remove files that are queued to be locally approved in CB
	conn = sqlite3.connect(local_db)
	c = conn.cursor()
	
	for index, row in df.iterrows():
		#see if file has been approved
		comp_name = PureWindowsPath(row['computerId_name']).stem
		c.execute("SELECT * FROM approved WHERE file_hash=? AND comp_name=?", (row['fileCatalogId_sha256'], comp_name))
		result = c.fetchall()
		#if file has been approved, drop it from the virus database
		if result:
			df.drop(index, inplace=True)
			
	
	c.close
	conn.close()
	#paths of infected files
	loc_df = df.filter(['computerId_name', 'pathName'], axis=1)

	#remove duplicate computer + filepath rows
	loc_df = loc_df.drop_duplicates()

	#infected files
	df = df.filter(['fileName', 'fileCatalogId_sha256'], axis=1)

	#remove duplicate hashes
	df = df.drop_duplicates(['fileCatalogId_sha256'])
		
	#write ClamAv database
	with open(virus_db, 'w') as f:
		for index, row in df.iterrows():
			f.write(row['fileCatalogId_sha256'] + ':*:' + row['fileName'] +  ':73\n')
	#TODO for testing purposes only, remove
	#	f.write('55f8718109829bf506b09d8af615b9f107a266e19f7a311039d1035f180b22d4:*:foobar.exe:73\n')

	f.close() 
	syslog.syslog(syslog.LOG_NOTICE, 'Virus database ' + str(Path(virus_db).resolve()) + ' created')

	return loc_df

def build_local_db(local_db):

	syslog.syslog(syslog.LOG_NOTICE, "No local database found, creating new one at " + local_db)
	conn = sqlite3.connect(local_db)
	c = conn.cursor()
	c.execute('CREATE TABLE IF NOT EXISTS quarantine (quarantine_loc TEXT PRIMARY KEY, source_loc TEXT NOT NULL, created_at timestamp)')
	c.execute('CREATE TABLE IF NOT EXISTS approved (file_hash TEXT NOT NULL, comp_name TEXT NOT NULL, PRIMARY KEY(file_hash, comp_name))') 
	c.close()
	conn.close()
	
def return_file(quarantine_db, credentials, filepath):
	#search for file path in quarantine database
	conn = sqlite3.connect(quarantine_db)
	c = conn.cursor()
	c.execute("SELECT * FROM quarantine WHERE source_loc LIKE ? ORDER BY created_at DESC", ('%' + filepath + '%',))
	result = c.fetchall()
	#print matching results (if any)
	selected = False
	if len(result) > 0:
		for item in enumerate([x[1:] for x in result]):
			print("[%d] %s %s" %(item[0], item[1][0], item[1][1]))
		#get user input to restore file
		try:
			idx = int(input("Please enter the corresponding number to the file you'd like to restore. If none of these files, enter -1: "))
		except ValueError:
			print("Invalid input entered")
			sys.exit()
		if idx > -1:
			try:
				source = result[idx][0] 
				dest =  result[idx][1]
				selected = True
			except IndexError:
				print("Invalid selection made")
		else:
			print("Exiting program")
			return 
	else:
		print("No matching files found")
		return 			

	#confirm movement of selected file
	confirmed = False
	if selected:
		question = "Confirm movement from " + source + " to " + dest + " ?[y/n]: "
		confirmation = input(question).lower().strip()
		if confirmation == 'y':
			confirmed = True
		else:
			return	
	else:
		return
		
	#replace quarantined file if it is not already in directory
	if confirmed:
		parent = Path(dest).parent
		comp_name = parent.parts[1]
		#try to mount target drive
		try:
			comp = Computer(comp_path=str(parent), credentials=credentials)
			comp.mount()
		except Exception as e:
			print(e)
			syslog.syslog(syslog.LOG_ALERT, "Failed to mount " + str(parent) + "exiting program")
			sys.exit()
		
		name = Path(dest).name
		s, d = Path(source), Path(comp.mount_point + '/' + name) 
		if not d.exists():
			shutil.move(str(s), str(d))
			#s.replace(d)
			syslog.syslog(syslog.LOG_ALERT, "FALSE POSITIVE RESTORED: " + source + " moved to " + dest)
			#remove left text file
			t = d.with_suffix('.txt')
			if t.exists:
				t.unlink()
				syslog.syslog(syslog.LOG_NOTICE, "Removing contact info at " + str(t))
			#remove quarantine record from database
			syslog.syslog(syslog.LOG_NOTICE, "Removing " + source + " listing from quarantine database")
			c.execute("DELETE FROM quarantine WHERE quarantine_loc = ?", (source,))
			conn.commit()
			sha_sum = sha256sum(str(d))
			#add approval record to database
			syslog.syslog(syslog.LOG_NOTICE, "Adding " + name + " on computer " + comp_name + " to local approval database")
			c.execute("REPLACE INTO approved VALUES (?,?)", (sha_sum, comp_name))
			conn.commit()
		else:
			print(str(d) + " already exists, aborting move")

		comp.unmount()
	
	#close connection
	c.close()
	conn.close()

	#attempt to remove parent directory(if empty)
	try:
		s.parent.rmdir()
	except OSError:
		pass 

def sha256sum(filepath):
	"""Calculates the hash of a file for whitelisting purposes"""
	sha256 = hashlib.sha256()
	#Read file in 64kb chunks
	BUF_SIZE = 65535  
	with open(filepath, 'rb') as f:
		while True:
			data = f.read(BUF_SIZE)
			if not data:
				break
			sha256.update(data)
	return sha256.hexdigest()

def approve_queue(token, local_db):

	#disable insecure request warning
	urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

	#prepare request
	authJson = {
		'X-Auth-Token': token,
		'content-type': 'application/json'
		}

	url = 'https://cbep/api/bit9platform/v1/FileInstance'
	b9StrongCert = False 

	#query approval database
	conn = sqlite3.connect(local_db)
	c = conn.cursor()
	c.execute("SELECT * FROM approved")
	approved_files = c.fetchall()
	
	for result in approved_files:
		syslog.syslog(syslog.LOG_NOTICE, 'Requesting matching file instance for ' + result[0] + ' on computer ' + result[1])
		query = {'expand': ['fileCatalogId', 'computerId'], 'q': ['fileCatalogId_sha256:' + result[0], 'computerId_name:*' + result[1]]}
	
		#send request for file instance with matching hash value on computer
		r = requests.get(url, params=query, headers=authJson, verify=b9StrongCert).json()
	
		#if no files are found, do not continue
		if not r:
			syslog.syslog(syslog.LOG_NOTICE, 'No matching files found')
		#otherwise, locally approve all matching files
		else:
			for finst in r:
				file_id = finst['id']
				finst['localState'] = 2
				del finst['id']
				syslog.syslog(syslog.LOG_ALERT, 'Locally approving ' + finst['fileName'] + ' on ' + result[1])
				requests.put(url + '/' + str(file_id), json.dumps(finst), headers=authJson, verify=b9StrongCert)	
			
			#remove from approval queue
			c.execute("DELETE FROM approved WHERE file_hash=? AND comp_name=?", (result[0], result[1])) 

	c.close()
	conn.close()

def delete_file(local_db, filepath):	
	#search for file path in quarantine database
	conn = sqlite3.connect(local_db)
	c = conn.cursor()
	c.execute("SELECT * FROM quarantine WHERE source_loc LIKE ? ORDER BY created_at DESC", ('%' + filepath + '%',))
	result = c.fetchall()
	#print matching results (if any)
	selected = False
	if len(result) > 0:
		for item in enumerate([x[1:] for x in result]):
			print("[%d] %s %s" %(item[0], item[1][0], item[1][1]))
		#get user input to restore file
		try:
			idx = int(input("Please enter the corresponding number to the file you'd like to delete. If none of these files, enter -1: "))
		except ValueError:
			print("Invalid input entered")
			sys.exit()
		if idx > -1:
			try:
				source = result[idx][0] 
				dest =  result[idx][1]
				selected = True
			except IndexError:
				print("Invalid selection made")
		else:
			print("Exiting program")
			
	else:
		print("No matching files found")
			

	#confirm deletion of selected file
	confirmed = False
	if selected:
		question = "Confirm deletion of " + source + " ?[y/n]: "
		confirmation = input(question).lower().strip()
		if confirmation == 'y':
			confirmed = True
	
	#if confirmed, remove file from database
	if confirmed:
		c.execute("DELETE FROM quarantine WHERE quarantine_loc = ?", (source,)) 
		#delete quarantine file
		Path(source).unlink()

	#close connection	
	c.close()
	conn.close()
