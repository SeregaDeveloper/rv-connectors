import requests
import json
import time
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
import configparser

config = configparser.ConfigParser()
config.read('settings.ini')

nad_url = config['nad']['url']
nad_pass = config['nad']['password']
nad_user = config['nad']['username']
rvison_ip = config['rvision']['ip']
rvision_key = config['rvision']['key']

session = requests.Session()
session.trust_env = False


def auth():

  global session
	
	url = f"{nad_url}/api/v2/auth/login"

	payload = json.dumps({
		"username": nad_user,
		"password": nad_pass
	})
	headers = {
		'Referer': f"{nad_url}/",
		'Content-Type': 'application/json'
	}

	response = session.post(url, headers=headers,verify=False, data=payload)
	return response.headers['Set-Cookie'].split("csrftoken=")[1].split(";")[0]

def get_events(csrf,src,dst,alert,time_from,time_to):

	global session
	url = f"{nad_url}/api/v2/bql?source=2"

	payload = f"SELECT \"pr\", \"msg\", \"cls\", \"success.affected\", \"ts\", \"attacker.ip\", \"attacker.geo.country\", \"victim.ip\", \"victim.geo.country\", \"sid\", \"attacker.dns\", \"victim.dns\", \"att_ck\", \"id\", extract_raw_object('false_positive'), (SELECT \"rpt.cat\", \"id\", \"start\", \"end\", \"flags\", \"state\", \"app_proto\", \"has_files\", \"rpt.color\", \"rpt.type\", \"rpt.where\", \"rpt.id\" FROM flow LIMIT 1)\r\nFROM alert\r\nWHERE \"ts\" >= {time_from} AND \"ts\" <= {time_to} AND EXISTS (SELECT * FROM flow WHERE \"end\" >= {time_from} AND \"end\" <= {time_to} AND (alert.pr == 1 && alert.msg == \"{alert}\" && alert.attacker.ip == {src} && alert.victim.ip == {dst}))\r\nORDER BY \"pr\" asc\r\nLIMIT 1"

	headers = {
		'Referer': f"{nad_url}/",
		'X-Csrftoken': csrf,
		'Content-Type': 'text/plain'
		}

	response = session.post(url, headers=headers, verify=False, data=payload)
	response  = json.loads(response.text)
	return response["result"]

def get_current_event_info(csrf,id,key,time_from,time_to):

	global session
	url = f"{nad_url}/api/v2/flow/{key}/alert/{id}?end={time_to}&source=2&start={time_from}"

	payload = ""
	headers = {
		'Referer': f"{nad_url}/",
		'X-Csrftoken': csrf
		}

	response = session.get(url, headers=headers, verify=False, data=payload)
	return json.loads(response.text)

def update_inc(id,sign,detect,name,src,dst,time,desc):

	url = f"https://{rvison_ip}/api/v2/incidents"

	payload = {
			'identifier': id,
			'detectDescription':sign,
			'description':desc,
			'events_data': f'{{\"detection\":\"{detect}\", \"name\":\"{name}\", \"src\":\"{src}\", \"dst\":\"{dst}\", \"time\":\"{time}\",\"source_id\":" "}}'
		}
	
	headers = {
		'X-Token' : rvision_key
	}

	response = requests.request("POST", url, headers=headers, verify = False,  data=payload)
	return response.text

tt = int(time.time())
tf = tt - (48*60*60)
tt *=1000
tf *=1000

csrf = auth()


try:
	events = get_events(csrf,sys.argv[1],sys.argv[2],sys.argv[3],tf,tt)
	for event in events:
		name = event[1]
		detect = event[2]
		time = event[4].replace("T"," ")
		id = event[13]
		key = str(event[15]).split("'")[1].split("\'")[0]

	event_info = get_current_event_info(csrf,id,key,tf,tt)
	sign = event_info["signature"]
	try:
		desc = str(detect)
	except:
		desc = " "
		update_inc(sys.argv[4],sign["rule"],detect,name,sys.argv[1],sys.argv[2],time,desc)

except:
	events = get_events(csrf,sys.argv[2],sys.argv[1],sys.argv[3],tf,tt)
	for event in events:
		name = event[1]
		detect = event[2]
		time = event[4].replace("T"," ")
		id = event[13]
		key = str(event[15]).split("'")[1].split("\'")[0]
	event_info = get_current_event_info(csrf,id,key,tf,tt)
	sign = event_info["signature"]
	try:
		desc = str(detect)
	except:
		desc = " "
	update_inc(sys.argv[4],sign["rule"],detect,name,sys.argv[2],sys.argv[1],time,desc)
