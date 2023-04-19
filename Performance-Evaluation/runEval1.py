import csv
import subprocess

allParams = ["clientSetSize", "serverSetSize", "intersectionSetSize", "nSimpleHF", "eachSimpleTableSize","eachCuckooTableSize", "maxPP"]
currentAlgoParams = ["-B", "128", "--perf"] #Standard ElGamal
runsPerConf = 10

with open("Parameters1.txt", "r") as param_file:
    tsv_reader = csv.DictReader(param_file, delimiter="\t")
    for readParam in tsv_reader:
        runParamString = currentAlgoParams.copy()

        for param in allParams:
            runParamString.append(f"--{param}")
            runParamString.append(f"{readParam[param]}")
            #print(f"--{param} {readParam[param]}")
        
        print(f"Run{runParamString} {runsPerConf} times")

        for i in range(0, runsPerConf):
            subprocess.Popen(["../build/src/ServerMain"] + runParamString)
            subprocess.run(["../build/src/ClientMain"] + runParamString)