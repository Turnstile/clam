import shlex
import syslog
import subprocess

class Computer:

	def __init__(self, comp_path, credentials, mount_point="/mnt/infected"):
		"""Constructor for Computer class
		
		:param comp_path: the path of the parent directory of the virus, in the form of //COMPUTERNAME/DRIVELETTER$/PATH
		:param credentials: the file containing the credentials used to mount the drive
		:param mount_point: where the comp_path is to be mounted locally
		"""
		self.comp_path = comp_path
		self.mount_point = mount_point
		self.credentials = credentials

	def mount(self):		
		"""Mount a network drive using the comp_path, mount_point, and username given in the constructor"""
		syslog.syslog(syslog.LOG_NOTICE, "Mounting " + self.comp_path + " to " + self.mount_point)
		#TODO for testing only, remove
		#cmd = "sudo mount --bind " + self.comp_path + " " + self.mount_point
		cmd = "sudo mount -t cifs " + '"' + self.comp_path + '"' + " " + self.mount_point + " -v -o credentials=" + self.credentials
		subprocess.run(shlex.split(cmd))
	
	def unmount(self):
		"""Unmount previously mounted network drive"""
		cmd = "sudo umount " + self.mount_point
		subprocess.run(shlex.split(cmd))
