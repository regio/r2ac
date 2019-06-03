#!/usr/bin/env python
import re
import os
nome = os.listdir(".")
#nome = ["10.0.0.101534355124.94","10.0.0.111534355129.93"]
#nome[0] ="10.0.0.101534355124.94"
#nome[2]="-orange 512mb"
#nome[3]="-SENDER"

for file in os.listdir("."):
#for i in range (0,11):
	if(file.startswith("10.")):
		shakes = open(file, "r")
		love = open(file+"opt1", "w")
		love2 =  open(file+"opt2", "w")
		love3 = open(file+"opt3", "w")
		love4 = open(file+"opt4", "w")
		love6 = open(file+"opt6", "w")
		for line in shakes:
			if re.match("(.*)=====1=====>time to generate key:(.*)", line):
				print >> love, line.split("=====1=====>time to generate key: ")[1],
			if re.match("(.*)=====2=====>time to add transaction in a block:(.*)", line):
				print >> love2, line.split("=====2=====>time to add transaction in a block: ")[1],
			if re.match("(.*)=====3=====>time to update transaction received:(.*)", line):
				print >> love3, line.split("=====3=====>time to update transaction received: ")[1],
			if re.match("(.*)=====4=====>time to add new block in peers:(.*)", line):
				print >> love4, line.split("=====4=====>time to add new block in peers: ")[1],
			if re.match("(.*)=====6=====>time to execute block consensus:(.*)", line):
				print >> love6, line.split("=====6=====>time to execute block consensus: ")[1],