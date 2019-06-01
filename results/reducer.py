#!/usr/bin/env python
import re
import os
nome = os.listdir(".")
#nome = ["10.0.0.101534355124.94","10.0.0.111534355129.93"]
#nome[0] ="10.0.0.101534355124.94"
#nome[2]="-orange 512mb"
#nome[3]="-SENDER"

counter =0
lines=['','','','','','','','','','']

for file in os.listdir("."):
#for i in range (0,11):
	if(file.startswith("option")):
		shakes = open(file, "r")
		love = open(file+"divided", "w")
		for line in shakes:
			lines[counter]=line
			counter=counter+1
			if (counter >= 10):
				withoutlinebreak = lines[0].rstrip('\n')+lines[1].rstrip('\n')+lines[2].rstrip('\n')+lines[3].rstrip('\n')+lines[4].rstrip('\n')+lines[5].rstrip('\n')+lines[6].rstrip('\n')+lines[7].rstrip('\n')+lines[8].rstrip('\n')+lines[9]
				print >> love, withoutlinebreak,
				counter=0
				