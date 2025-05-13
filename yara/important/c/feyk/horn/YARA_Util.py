#This script can identify and remove duplicate rules (based on rule name) from YARA files contained within a directory.
#Duplicate rules are logged to duplicate.log in the current directory.
#Rule names are echoed to standard out.
#Be sure to backup your data before using the remove option.

#Copyright (c) 2020 Ryan Boyle randomrhythm@rhythmengineering.com.
#All rights reserved.

#This program is free software: you can redistribute it and/or modify
#it under the terms of the GNU General Public License as published by
#the Free Software Foundation, either version 3 of the License, or
#(at your option) any later version.

#This program is distributed in the hope that it will be useful,
#but WITHOUT ANY WARRANTY; without even the implied warranty of
#MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#GNU General Public License for more details.

#You should have received a copy of the GNU General Public License
#along with this program.  If not, see <http://www.gnu.org/licenses/>.


import os
from optparse import OptionParser
import sys
import datetime

def build_cli_parser():
    parser = OptionParser(usage="%prog [options]", description="Find duplicate YARA rules in a directory")
    parser.add_option("-r", "--remove", help="Remove duplicate rules", action="store_true")
    parser.add_option("-d", "--directory", action="store", default=None, dest="YARA_Directory_Path",
                      help="Folder path to directory containing YARA files")
    parser.add_option("-c", "--consolidate", action="store", default=None, dest="YARA_File_Path",
                      help="File path for consolidated YARA file")
    parser.add_option("-m", "--modify", help="Modify the file to rename duplicate rules", action="store_true")
    parser.add_option("-i", "--index", action="store", default=None, dest="YARA_Index_Path",
                      help="Create an index of YARA files") 
    parser.add_option("-t", "--type", action="store", default=None, dest="YARA_Index_Type",
                      help="Index YARA files based on parent folder match.") 
    parser.add_option("-b", "--BaseDirectory", action="store", default=None, dest="Base_Folder_Path",
                      help="Base folder to mark as current directory ./") 
    parser.add_option("-s", "--subdirectories", help="Recurse into subdirectories", action="store_true")
    parser.add_option("-v", "--verboselog", help="log all rules and the associated file", action="store_true")
    return parser
    
def ProcessRule(lstRuleFile, strYARApath, strOutPath):
  strYARAout = ""
  strLogOut = ""
  boolExcludeLine = False
  boolOverwrite = False
  if strOutPath == "":
    strOutPath = strYARApath
  for strRuleLine in lstRuleFile:
    strRuleOut = strRuleLine
    nameDepth = 0
    if strRuleLine[:5] == "rule ":
      nameDepth = 5
    elif strRuleLine[:13] == "private rule ":
      nameDepth = 13
    if nameDepth != 0:  
      strRuleName = strRuleLine[-(len(strRuleLine) -nameDepth):]
      strRuleName = strRuleName[:len(strRuleName) -1]
      if strRuleName[-1:] == "\r":
        strRuleName = strRuleName[:-1]
      if strRuleName[-1:] == "{":
        strRuleName = strRuleName[:-1]
      if strRuleName[-1:] == " ":
        while strRuleName[-1:] == " ":
          strRuleName = strRuleName[:-1]
      print (strRuleName)
      if boolLogging == True:
        logToFile(strCurrentDirectory + "/all_rules.csv",strRuleName + "," + strYARApath + "\n", False, "a")
      if strRuleName in dictRuleName:
        #print "duplicate rule in file " + strYARApath + " : " + strRuleName
        strLogOut = strLogOut + "Duplicate rule " + "\n" + strRuleName + " in " + dictRuleName[strRuleName]  + "\n" + strRuleName + " in " + strYARApath + "\n"
        if boolRename == False:
            boolExcludeLine = True
            
            if boolRemoveDuplicate == True:
              boolOverwrite = True
              strLogOut = strLogOut + "Removed rule " + strRuleName + " from " + strYARApath + "\n"
        else:
            intCount = 1
            while strRuleName + "_" + str(intCount) in dictRuleName:
                intCount += 1
            strRuleOut = str.replace(strRuleOut, strRuleName, strRuleName + "_" + str(intCount))
            strLogOut = strLogOut + "Renamed " + strRuleName + " to " + strRuleName + "_" + str(intCount) + " from " + strYARApath + "\n"
            strYARAout = strYARAout + strRuleOut
            boolOverwrite = True
      else:
        dictRuleName[strRuleName] = strYARApath
        strYARAout = strYARAout + strRuleOut
        boolExcludeLine = False
    elif boolExcludeLine == False:
      strYARAout = strYARAout + strRuleLine
  if strOutPath != strYARApath:
    strYARAout = strYARAout + "\n" #extra new line to separate rules in combined file
    logToFile(strOutPath,strYARAout, False, "a")
  elif boolOverwrite == True:
    logToFile(strYARApath,strYARAout, True, "w")
  if len(strLogOut) > 1:
    strLogOut = "-------------" + "\n" + strLogOut  
  logToFile(strCurrentDirectory + "/duplicate.log",strLogOut, False, "a")
  
def logToFile(strfilePathOut, strDataToLog, boolDeleteFile, strWriteMode):
    with open(strfilePathOut, strWriteMode) as target:
      if boolDeleteFile == True:
        target.truncate()
      target.write(strDataToLog)


def createIndexFile(boolNew, strFilePath, yaraPath, baseDir): # if index creation is not working on Windows check that you are escaping backslashes
  includePath = ""
  if boolNew == True:
    logToFile(strFilePath, "/*\n", False, "a")
    logToFile(strFilePath, "Generated by YARA_Rules_Util\n", False, "a")
    logToFile(strFilePath, "On " + str(datetime.date.today()) + "\n", False, "a")
    logToFile(strFilePath, "*/\n", False, "a")
  if "\\" in yaraPath or "/" in yaraPath: #windows or nix directory
    if "\\" in yaraPath:
      splitChar = "\\"
    else:
      splitChar = "/"
    arrayPath = yaraPath.split(splitChar) #need to determine the relative path between strFilePath and yaraPath. If different then use full file path. If same then truncate appropriatly
    for i in range(len(arrayPath),0, -1):
      if includePath == "":
        includePath = arrayPath[i -1]
      else:
        includePath = arrayPath[i -1] + "/" + includePath
      if arrayPath[i -2] == baseDir:
        break
    if i != 1:
      includePath = "./" + includePath
    else:
      includePath = yaraPath
    includeStatement = "include \"" + includePath + "\""
    logToFile(strFilePath, includeStatement + "\n", False, "a")

def fast_scandir(dirname): #https://stackoverflow.com/questions/973473/getting-a-list-of-all-subdirectories-in-the-current-directory/38245063
    subfolders= [f.path for f in os.scandir(dirname) if f.is_dir()]
    for dirname in list(subfolders):
        subfolders.extend(fast_scandir(dirname))
    return subfolders

boolRemoveDuplicate = False
boolRename = False
boolRecurse = False
boolLogging = False
folderMatch = ""
indexPath = ""
outputPath = ""
baseDirectory = ""
dictExclude = {"deprecated", "index.yar", "_index", "index_"}
strCurrentDirectory = os.getcwd()
strYARADirectory = os.getcwd()
parser = build_cli_parser()
opts, args = parser.parse_args(sys.argv[1:])
if opts.remove:
  boolRemoveDuplicate = True
if opts.subdirectories:  
  boolRecurse = True
  print("recusing subdirectories")
if opts.verboselog:
  boolLogging = True
if opts.YARA_Index_Path:
  indexPath = opts.YARA_Index_Path
  print("creating index file: " + indexPath)
  boolNewIndex = True
if opts.YARA_Index_Type:
  folderMatch = opts.YARA_Index_Type
if opts.Base_Folder_Path:
  baseDirectory = opts.Base_Folder_Path
if opts.YARA_Directory_Path:
  strYARADirectory = opts.YARA_Directory_Path
else:
  print ("Missing required parameter argument")
  exit()
if opts.modify:
  boolRename = True
if opts.YARA_File_Path:
  outputPath = opts.YARA_File_Path
dictRuleName = dict()
print (strYARADirectory)
logToFile(strCurrentDirectory + "\\duplicate.log","Started " + str(datetime.datetime.now()) + "\n", False, "a")

if boolRecurse == True:
  parentDir = fast_scandir(strYARADirectory)
  parentDir.append(strYARADirectory)
  parentDir.sort()
else:
  parentDir = {strYARADirectory}
print(parentDir)
for scanDirs in parentDir:
  for i in os.listdir(scanDirs):
    if i.endswith(".yar") or i.endswith(".yara"): 
      if opts.YARA_File_Path != '' and folderMatch != '': #File path for consolidated YARA file and folderMatch file type both provided  
        if not scanDirs.endswith(folderMatch): # Not the file type specified so move to next file
          continue
      if indexPath == "":
        print (i)
        with open(scanDirs + '/' + i, encoding='utf-8', errors='ignore') as f:
          lines = f.readlines()
          ProcessRule(lines, scanDirs + '/' + i, outputPath)
      else: #create index
        boolIndexExclude = False
        for excludeItem in dictExclude:
          if excludeItem in scanDirs + '/' + i:
            boolIndexExclude = True
        if folderMatch != "" and not scanDirs.endswith(folderMatch):
          boolIndexExclude = True
        if boolIndexExclude == False:
          createIndexFile(boolNewIndex, indexPath,  scanDirs + '/' + i, baseDirectory)
          boolNewIndex = False
          #print("indexing file: " +  scanDirs + '/' + i)
    else:
        continue
logToFile(strCurrentDirectory + "/duplicate.log","Completed " + str(datetime.datetime.now()) + "\n", False, "a")        
        

