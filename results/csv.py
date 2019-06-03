#!/usr/bin/env python
import re
import os
import csv
nome = os.listdir(".")

def initfile(fname):
		f = open(fname, "a+")
		f.write(";")
		f.close()


option1 = "option1.csv"
initfile(option1)
option2 = "option2.csv"
initfile(option2)
option3 = "option3.csv"
initfile(option3)
option4 = "option4.csv"
initfile(option4)
option6 = "option6.csv"
initfile(option6)

for file in os.listdir("."):

	if(file.endswith("opt1")):
		print("File="+str(file))
		source = open(file, "r")
		f = open(option1, "a+")
		for line in source:
			f.write(line+";")
		f.close()
		source.close()
		os.remove(file)

	if(file.endswith("opt2")):
		print("File="+str(file))
		source = open(file, "r")
		f = open(option2, "a+")
		for line in source:
			f.write(line+";")
		f.close()
		source.close()
		os.remove(file)

	if(file.endswith("opt3")):
		print("File="+str(file))
		source = open(file, "r")
		f = open(option3, "a+")
		for line in source:
			f.write(line+";")
		f.close()
		source.close()
		os.remove(file)

	if(file.endswith("opt4")):
		print("File="+str(file))
		source = open(file, "r")
		f = open(option4, "a+")
		for line in source:
			f.write(line+";")
		f.close()
		source.close()
		os.remove(file)

	if(file.endswith("opt6")):
		print("File="+str(file))
		source = open(file, "r")
		f = open(option6, "a+")
		for line in source:
			f.write(line+";")
		f.close()
		source.close()
		os.remove(file)

