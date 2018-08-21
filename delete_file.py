from db_ops import delete_file
import argparse, configparser

parser = argparse.ArgumentParser()
config = configparser.ConfigParser()
config.read('config.ini')
quarantine_db = config['Default']['Quarantine Database']
parser.add_argument('file', nargs='?', default='', help='Name of file to be restored')
filepath = parser.parse_args().file

delete_file(quarantine_db, filepath)
