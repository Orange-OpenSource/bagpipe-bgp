# vim: tabstop=4 shiftwidth=4 softtabstop=4
# encoding: utf-8

# Copyright 2014 Orange
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# 
#    http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.


import subprocess


def runCommand(log,command,raiseExceptionOnError=True,acceptableReturnCodes=[0]):
    '''
    Executes 'command' in a subshell.
    Returns (command_output,exitCode)
        - command_output is the list of lines output on stdout by the command
    Raises an exception based on the following:
        - will only raise an Exception if raiseExceptionOnError optional parameter is True
        - the exit code is acceptable
        - exit code is acceptable by default if it is zero
        - exit code is acceptable if it is in the (optional) acceptableReturnCodes list parameter
        - putting -1 in the acceptableReturnCodes list means that *any* exit code is acceptable 
    '''
    log.info("Running command: %s   [raiseExceptionOnError:%s]" % (command,raiseExceptionOnError))
    process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    # Poll process for new output until finished
    output=[]
    while True:
        nextline = process.stdout.readline().strip("\n")
        if nextline == '' and process.poll() != None:
            break
        if nextline != '':
            log.debug("runCommand output: %s" % nextline.rstrip())
            output.append(nextline)
        
    exitCode = process.returncode
    
    if (exitCode in acceptableReturnCodes) or (-1 in acceptableReturnCodes):
        return (output,exitCode)
    else:
        if len(output) > 0:
            message = "Exit code %d when running command ('%s') : %s" % (exitCode,command,output[-1])
        else:
            message = "Exit code %d when running command ('%s') : <no output>" % (exitCode,command)

        if raiseExceptionOnError:
            log.error(message)
            raise Exception(message)
        else:
            log.warning(message)
            return (output,exitCode)
