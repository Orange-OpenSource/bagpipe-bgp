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


import os
import shlex
import subprocess
import threading

from oslo_rootwrap import client


class RootwrapDaemonHelper(object):
    __client = None
    __lock = threading.Lock()

    def __new__(cls):
        """There is no reason to instantiate this class"""
        raise NotImplementedError()

    @classmethod
    def get_client(cls, root_helper_daemon):
        with cls.__lock:
            if cls.__client is None:
                cls.__client = client.Client(
                    shlex.split(root_helper_daemon))
            return cls.__client


def _rootwrap_command(log, root_helper_daemon, command, stdin=None,
                      raise_on_error=True, acceptable_return_codes=[0],
                      shell=False):
    '''
    Executes 'command' in a subshell.
    Returns (command_output,exit_code)
        - command_output is the list of lines output on stdout by the command
    Raises an exception based on the following:
        - will only raise an Exception if raise_on_error optional
          parameter is True
        - the exit code is acceptable
        - exit code is acceptable by default if it is zero
        - exit code is acceptable if it is in the (optional)
          acceptable_return_codes list parameter
        - putting -1 in the acceptable_return_codes list means that *any* exit
        code is acceptable
    '''
    log.info("Running rootwrapped command: %s   [stdin:%s, raise_on_error:%s]",
             command, stdin, raise_on_error)
    rootwrap_client = RootwrapDaemonHelper.get_client(root_helper_daemon)

    if shell:
        exit_code, output, error = rootwrap_client.execute(
                                        ["sh", "-c", command], stdin)
    else:
        exit_code, output, error = rootwrap_client.execute(command.split(),
                                                           stdin)

    if (exit_code in acceptable_return_codes or -1 in acceptable_return_codes):
        return (output.splitlines(), exit_code)
    else:
        message = \
            "Exit code %d when running '%s': %s" % (exit_code, command,
                                                    error)

        if raise_on_error:
            log.error(message)
            raise Exception(message)
        else:
            log.warning(message)
            return (output, exit_code)


def _shell_command(log, command, stdin=None, raise_on_error=True,
                   acceptable_return_codes=[0]):
    '''
    Executes 'command' in a subshell.
    Returns (command_output,exit_code)
        - command_output is the list of lines output on stdout by the command
    Raises an exception based on the following:
        - will only raise an Exception if raise_on_error optional
          parameter is True
        - the exit code is acceptable
        - exit code is acceptable by default if it is zero
        - exit code is acceptable if it is in the (optional)
          acceptable_return_codes list parameter
        - putting -1 in the acceptable_return_codes list means that *any* exit
        code is acceptable
    '''
    log.info("Running shell command: %s   [raise_on_error:%s]",
             command, raise_on_error)
    process = subprocess.Popen(
        command, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT)
    if stdin:
        process.stdin.write(stdin)
        process.stdin.close()
    # Poll process for new output until finished
    output = []
    while True:
        nextline = process.stdout.readline().strip("\n")
        if nextline == '' and process.poll() is not None:
            break
        if nextline != '':
            log.debug("run_command output: %s", nextline.rstrip())
            output.append(nextline)

    exit_code = process.returncode

    if (exit_code in acceptable_return_codes or -1 in acceptable_return_codes):
        return (output, exit_code)
    else:
        if len(output) > 0:
            message = \
                "Exit code %d when running '%s': %s" % (exit_code, command,
                                                        output[-1])
        else:
            message = \
                "Exit code %d when running '%s' (no output)" % (exit_code,
                                                                command)

        if raise_on_error:
            log.error(message)
            raise Exception(message)
        else:
            log.warning(message)
            return (output, exit_code)


def run_command(log, root_helper_daemon, root_helper, command,
                run_as_root=False, *args, **kwargs):
    if run_as_root and os.geteuid() == 0:
        # do not need to wrap any call
        run_as_root = False

    if run_as_root and root_helper_daemon:
        return _rootwrap_command(log, root_helper_daemon,
                                 command, *args, **kwargs)
    else:
        if run_as_root:
            command = " ".join([root_helper, command])

        # remove shell from kwargs (uses shell by default)
        kwargs.pop("shell", False)
        return _shell_command(log, command, *args, **kwargs)
