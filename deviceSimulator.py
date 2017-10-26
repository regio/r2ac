import sys
import requests
import json

server= "localhost"

def setServer():
	global server
	server = raw_input('Gateway IP:')

def authReq():
	headers = {'Content-type': 'application/json'}
	payload = {'publicKey': '-----BEGIN PUBLIC KEY-----\nMFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAOz+gypueDYyxO2o8k5LNvfBRCXhyTcR\nk/uw4200ICXWSo0Ol/ZWFvIrbYjJ73bOqgy/eXmBYGQrzttmE3db1NUCAwEAAQ==\n-----END PUBLIC KEY-----\n'}
	r = requests.post("http://"+server+":3001/auth", data=json.dumps(payload), headers=headers)
	

def sendData():
	print "sending"


#############################################################################
#############################################################################
######################          Main         ################################
#############################################################################
#############################################################################
def main():
	global server
	options = {1 : setServer,
		2 : authReq,
		3 : sendData
    }	

	mode=-1
	while True:
		print("Choose your option ["+server+"]")
		print("0 - Exit")
		print("1 - Set Server Address")
		print("2 - Authentication Request")
		print("3 - DecriptReceivedAESKey - sign data - encrypt with AES key - Send to Gateway")
		print("666 - Butistrepy")
		try:
			mode=int(raw_input('Input:'))
		except ValueError:
			print "Not a number"
		if(mode==0):
			break
		options[mode]()



if __name__ == '__main__':

    if len(sys.argv[1:]) < 1:
        print ("Command Line usage:")
        print ("    python deviceSimulator.py TBD")
        quit()
    main()