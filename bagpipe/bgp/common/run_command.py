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
import threading

from oslo_config import cfg
from oslo_log import log as logging
from oslo_rootwrap import client
import shlex


common_opts = [
    cfg.StrOpt("root_helper", default="sudo",
               help="Root helper command."),
    cfg.StrOpt("root_helper_daemon",
               help="Root helper daemon application to use when possible."),
]

cfg.CONF.register_opts(common_opts, "COMMON")


class RootwrapDaemonHelper(object):
    __client = None
    __lock = threading.Lock()

    def __new__(cls):
        """There is no reason to instantiate this class"""
        raise NotImplementedError()

    @classmethod
    def get_client(cls):
        with cls.__lock:
            if cls.__client is None:
                cls.__client = client.Client(
                    shlex.split(cfg.CONF.COMMON.root_helper_daemon))
            return cls.__client


def _rootwrap_command(log, command, stdin=None,
                      shell=False):
    '''
    Executes 'command' in rootwrap mode.
    Returns (exit_code, command_output command_error)
        - command_output is the list of lines output on stdout by the command
        - command_error is the list of lines error on stderr by the command
    '''
    rootwrap_client = RootwrapDaemonHelper.get_client()

    if shell:
        exit_code, output, error = rootwrap_client.execute(["sh",
                                                            "-c", command],
                                                           stdin)
    else:
        exit_code, output, error = rootwrap_client.execute(command.split(),
                                                           stdin)

    return (exit_code, output, error)


def _shell_command(log, command, stdin=None):
    '''
    Executes 'command' in subshell mode.
    Returns (exit_code, command_output, command_error)
        - command_output is the list of lines output on stdout by the command
        - command_error is the list of lines error on stderr by the command
    '''
    process = subprocess.Popen(command, shell=True,
                               stdin=subprocess.PIPE,
                               stdout=subprocess.PIPE,
                               stderr=subprocess.PIPE)

    (output, error) = process.communicate(stdin)

    exit_code = process.returncode
    return (exit_code, output, error)


def _log_output_error(log_fn, output, error):
    if output:
        log_fn("  run_command stdout: %s", "\n   ".join(output))
    if error:
        log_fn("  run_command stderr: %s", "\n".join(error))


def run_command(log, command,
                run_as_root=False, raise_on_error=True,
                acceptable_return_codes=[0], *args, **kwargs):
    '''
    Executes 'command' in subshell or rootwrap mode.
    Returns (command_output, exit_code)
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
    if run_as_root and cfg.CONF.COMMON.root_helper_daemon:
        log.debug("Running command in rootwrap mode: %s", command)
        exit_code, output, error = _rootwrap_command(log,
                                                     command, *args, **kwargs)
    else:
        log.debug("Running command in subshell mode: %s ", command)
        if run_as_root:
            command = " ".join([cfg.CONF.COMMON.root_helper, command])

        # remove shell from kwargs (uses shell by default)
        kwargs.pop("shell", False)
        exit_code, output, error = _shell_command(log, command,
                                                  *args, **kwargs)

    output = output.splitlines()
    error = error.splitlines()

    if log.isEnabledFor(logging.DEBUG):
        _log_output_error(log.debug, output, error)

    if (exit_code in acceptable_return_codes or -1 in acceptable_return_codes):
        return (output, exit_code)
    else:
        message = "Exit code %d when running '%s'" % (exit_code, command)

        if raise_on_error:
            log.error(message)
            _log_output_error(log.error, output, error)
            raise Exception(message)
        else:
            log.warning(message)
            return (output, exit_code)
