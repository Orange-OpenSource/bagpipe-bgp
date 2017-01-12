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

import functools

from oslo_log import log as logging


# inspired from neutron.log
def log(method, level=logging.DEBUG):
    """Decorator helping to log method calls."""

    @functools.wraps(method)
    def wrapper(*args, **kwargs):
        instance = args[0]
        data = {"class_name": "%s.%s" % (instance.__class__.__module__,
                                         instance.__class__.__name__),
                "method_name": method.__name__,
                "args": args[1:], "kwargs": kwargs}
        if hasattr(args[0], 'log'):
            logger = args[0].log
        else:
            logger = logging.getLogger(method.__module__)
        logger.log(level, '%(class_name)s method %(method_name)s'
                   ' called with arguments %(args)s %(kwargs)s', data)
        return method(*args, **kwargs)
    return wrapper


def log_info(method):
    return log(method, logging.INFO)
