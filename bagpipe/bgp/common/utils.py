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

import re
from collections import defaultdict

from oslo_concurrency import lockutils
from oslo_config import cfg


def synchronized(method):

    def synchronized_method(self, *arg, **kws):
        with self.lock:
            return method(self, *arg, **kws)

    return synchronized_method


oslo_synchronized = lockutils.synchronized_with_prefix('bagpipe-bgp-')


def plural(x):
    if len(x) > 1:
        return "s"
    else:
        return ""


def invert_dict_of_sets(d):
    '''
    return inverted dict of sets from original dict containing sets of
    non-unique hashable items
    '''
    new_d = defaultdict(set)
    for k in d:
        for v in d[k]:
            new_d[v].add(k)
    return new_d


camel2underscore_regex = re.compile('(?!^)([A-Z]+)')


def dict_camelcase_to_underscore(dictionary):
    ''' copy dict, with translation of keys from FooBar to foo_bar'''
    return {camel2underscore_regex.sub(r'_\1', key).lower(): value
            for (key, value) in dictionary.iteritems()
            }


def osloconfig_json_serialize(obj):
    if (isinstance(obj, cfg.ConfigOpts) or
            isinstance(obj, cfg.ConfigOpts.GroupAttr)):
        return {osloconfig_json_serialize(k): osloconfig_json_serialize(v)
                for k, v in obj.iteritems()}
    return obj
