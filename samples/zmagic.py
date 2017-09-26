#!/usr/bin/env python
import re
nome1="-orange 256mb"
nome2="-orange 512mb"
nome3="-SENDER"

for i in range (1,11):
	shakes = open(str(i)+nome1, "r")
	love = open("limpo_request"+str(i)+nome1, "w")
	love2 = open("limpo_addinfo"+str(i)+nome1, "w")
	for line in shakes:
		if re.match("(.*)time between requests:(.*)", line):
			print >> love, line,
		if re.match("(.*)time to add new info:(.*)", line):
			print >> love2, line,

for i in range (1,11):
	shakes = open(str(i)+nome2, "r")
	love = open("limpo_request"+str(i)+nome2, "w")
	love2 = open("limpo_addinfo"+str(i)+nome2, "w")
	for line in shakes:
		if re.match("(.*)time between requests:(.*)", line):
			print >> love, line,
		if re.match("(.*)time to add new info:(.*)", line):
			print >> love2, line,

for i in range (1,11):
	shakes = open(str(i)+nome3, "r")
	love = open(str(i)+nome3, "w")
	for line in shakes:
		if re.match("(.*)Time in mili to send request:(.*)", line):
			print >> love, line,
