import shlex
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


def rootwrap_command(log, root_helper_daemon, command, stdin=None,
                     raise_on_error=True, acceptable_return_codes=[0],
                     shell=False):
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
