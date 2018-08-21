README V1.0 / JULY 2018

Clamscan
========

Introduction
------------
The purpose of this project is to automate the quarantining of files marked as potential risks by Carbon Black Protect. It is also capable of returning quarantined files that were false positives, and locally approving these false positives in Carbon Black.

How it Works
------------
When run hourly, the scan_computers.py script will pull down a list of all the unique file hashes of files marked as "potential risks" by carbon black since the last time it was run. If any files are found, it will then mount each path where these files are located and run a clamscan using the pulled file hashes as a virus signature database. Any detections will be moved to the specified quarantine folder and renamed as "<virusname>.<extension>.<UUID>.quarantine". In the quarantined virus' place, a text file named after the original file will be left containing a brief message and contact information for the helpdesk.

When a file is quarantined, an entry is made in a virus database keeping track of where the file originally came from, and where it is located in the quarantine folder. If the file is deemed to be a false positive, it can be returned using the return_file.py script. This launches an interactive prompt that allows the user to determine select the false positive in question, and returns it to its original location.     

Usage
------
The usage of this program is controlled by the clam.sh bash script, which should be run as an hourly chron job. To manually run the scan, simply run the scan_computers.py file directly.

To return and locally approve false positive files, run the return_file.py file directly.

IMPORTANT NOTE: Currently these files must be run with root access. In the future, it may be possible to add users to a permitted group, or to allow users individual file access.

For more information about how to run these files manually, please refer to the documentation file found in this directory.

Help
----
To get help with this, please contact John Bradshaw at John.Bradshaw2@traviscountytx.gov

However, because I am a summer intern, if I am not around to answer questions please get in touch with Kala Kinyon (Kala.Kinyon@traviscountytx.gov) or Paul Knight (Paul.Knight@traviscountytx.gov)

Author
------
John Bradshaw
