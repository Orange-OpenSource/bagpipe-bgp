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

import logging as python_logging
from oslo_log import log as logging

import re
import urllib
import six

LOG = logging.getLogger(__name__)

VALUE = 'VALUE'
SUBITEM = 'SUBITEM'
SUBTREE = 'SUBTREE'
FORWARD = 'FORWARD'
COLLECTION = 'COLLECTION'
DELEGATE = 'DELEGATE'


def _split_lg_path(path_prefix, path):
    if len(path) == 0:
        return (None, None, path_prefix)
    else:
        return (path[0], path[1:],
                "%s/%s" % (path_prefix, urllib.quote(path[0])))


def _get_lg_local_info_recurse(obj, cls, path_prefix):

    if cls == LookingGlassMixin:
        return {}

    result = cls.get_log_local_info(obj, path_prefix)

    assert isinstance(result, dict)

    for base in cls.__bases__:
        if issubclass(base, LookingGlassMixin):
            result.update(
                _get_lg_local_info_recurse(obj, base, path_prefix))

    return result


def _get_lg_map_recurse(obj, cls):

    if cls == LookingGlassMixin:
        return {}

    result = cls.get_lg_map(obj)

    for base in cls.__bases__:
        if issubclass(base, LookingGlassMixin):
            result.update(_get_lg_map_recurse(obj, base))
        else:
            LOG.debug("not recursing into %s", base)

    return result


def _lookup_path(my_dict, path):
    ''' lookup path in dict'''
    assert isinstance(path, (list, tuple))

    if len(path) == 0:
        return my_dict

    # len(path)>0
    if not isinstance(my_dict, dict):
        raise KeyError(path[0])
    else:
        return _lookup_path(my_dict[path[0]], path[1:])


def get_lg_prefixed_path(path_prefix, path_items):
    fmt = "%s" + ('/%s' * len(path_items))
    quoted_path_items = [urllib.quote(path_item) for path_item in path_items]
    quoted_path_items.insert(0, path_prefix)
    return fmt % tuple(quoted_path_items)


class LookingGlassMixin(object):

    def _get_lg_map(self):
        """not to be overridden: calls get_lg_map, on each of the super classes
           and merge the result in a dict
        """
        return _get_lg_map_recurse(self, self.__class__)

    def get_lg_map(self):
        """
        Can be overriden by looking glass objects to indicate looking
        glass information items for this objects.

        :returns: a dict mapping a <subpath> to a (<lg_map_type>,<hook>) tuple

        if lg_map_type is VALUE, then the looking glass information for
            <subpath> will be <hook>
        if lg_map_type is SUBITEM, then <hook> is supposed to be a function
            and the looking glass information for <subpath> will be the result
            of calling hook()
        if lg_map_type is SUBTREE, then <hook> is supposed to be a function and
            the looking glass information for <subpath> will be the result of
            calling hook(path_prefix), but this information will only be
            produced if the <subpath> is queried (not produced if the full
             object is queried)
        if lg_map_type is FORWARD, then <hook> is supposed to be a looking
            glass object and the looking glass information for <subpath>
            will be the looking glass information for <subpath> of object
            <hook>
        if lg_map_type is DELEGATE, then <hook> is supposed to be a looking
            glass object and the looking glass information for <subpath> will
            be the full looking glass information for object <hook>
        if lg_map_type is COLLECTION, then <hook> is supposed to be a tuple of
            functions (list_callback,target_callback). list_callback() is
            expected
            to return a list of string, each string identifying a looking
            glass object target_callback(string) is expected to return the
            looking glass object corresponding to <string>

            if *self* is directly queried, the information returned is just a
            list of dict containing "href" values pointing to each object in
            the collection
            if a <subpath> is queried, the information returned is the
            looking glass information for the object corresponding to
            <subpath>
        """
        return {}

    def _get_log_local_info(self, path_prefix):
        """
        not to be overridden: calls get_log_local_info, on each of
          the super classes and merge the result in a dict
        """
        return _get_lg_local_info_recurse(self, self.__class__, path_prefix)

    def get_log_local_info(self, path_prefix):
        """
        Can be overriden by looking glass objects.

        :param path_prefix: the URL prefix that was used to reach *self*
            through the looking glass
        :returns: a dict that will be serialized as JSON and passed to the
            looking glass client, either as is, or if a sub path was queried,
            the dict value corresponding to the first item of the path
        """
        return {}

    def get_looking_glass_info(self, path_prefix="", path=None):
        """
        This method builds the looking glass information for *self* based on
        the looking glass map

        *not* to be overridden by looking glass objects
        """
        if path is None:
            path = []

        (first_segment,
         path_reminder,
         new_path_prefix) = _split_lg_path(path_prefix, path)

        lg_map = self._get_lg_map()

        if first_segment in lg_map:
            (mapping_type, mapping_target) = lg_map[first_segment]
            LOG.debug("Delegation for path_item '%s': %s:%s ",
                      first_segment, mapping_type, mapping_target)

            if mapping_type == VALUE:
                return mapping_target

            if mapping_type == FORWARD:
                LOG.debug(
                    "   Forwarded '%s' to target %s...", path, mapping_target)
                if not isinstance(mapping_target, LookingGlassMixin):
                    LOG.error("Delegation target for '%s' at '%s' does not "
                              "implement LookingGlassMixin!",
                              first_segment, new_path_prefix)
                    raise NoSuchLookingGlassObject(new_path_prefix,
                                                   first_segment)
                return mapping_target.get_looking_glass_info(path_prefix, path)

            if mapping_type == FORWARD:
                LOG.debug(
                    "   Forwarded '%s' to target %s...", path, mapping_target)
                if not isinstance(mapping_target, LookingGlassMixin):
                    LOG.error("Delegation target for '%s' at '%s' does not "
                              "implement LookingGlassMixin!",
                              first_segment, new_path_prefix)
                    raise NoSuchLookingGlassObject(new_path_prefix,
                                                   first_segment)
                return mapping_target.get_looking_glass_info(path_prefix, path)

            elif mapping_type == DELEGATE:
                LOG.debug(
                    "   Delegated '%s' to delegation target %s ...",
                    path, mapping_target)
                if not isinstance(mapping_target, LookingGlassMixin):
                    LOG.error("Delegation target for '%s' at '%s' does not "
                              "implement LookingGlassMixin!",
                              first_segment, new_path_prefix)
                    raise NoSuchLookingGlassObject(new_path_prefix,
                                                   first_segment)
                return mapping_target.get_looking_glass_info(new_path_prefix,
                                                             path_reminder)

            elif mapping_type == SUBITEM:
                LOG.debug("   Sub-item callback: %s", first_segment)
                try:
                    return _lookup_path(mapping_target(), path_reminder)
                except KeyError as e:
                    raise NoSuchLookingGlassObject(new_path_prefix, str(e))

            elif mapping_type == SUBTREE:
                LOG.debug("   Subtree callback: %s(...)", first_segment)
                try:
                    return _lookup_path(mapping_target(new_path_prefix),
                                        path_reminder)
                except KeyError as e:
                    raise NoSuchLookingGlassObject(new_path_prefix, str(e))

            elif mapping_type == COLLECTION:
                LOG.debug("   Collection callback...")

                (list_callback, target_callback) = mapping_target

                (second_segment, path_reminder, newer_path_prefix) = \
                    _split_lg_path(new_path_prefix, path_reminder)
                if second_segment is None:
                    LOG.debug("   Getting list elements: %s", list_callback)
                    result = []
                    for x in list_callback():
                        x["href"] = get_lg_prefixed_path(path_prefix,
                                                         [first_segment,
                                                          x["id"]])
                        result.append(x)
                    return result
                else:
                    LOG.debug("   Callback -> resolve subItem '%s' with %s "
                              "and follow up get_looking_glass_info(...'%s')",
                              second_segment, target_callback, path_reminder)
                    try:
                        # TODO: catch errors
                        target = target_callback(second_segment)
                        if target is None:
                            LOG.error("No delegation target for '%s' at '%s' ",
                                      second_segment, new_path_prefix)
                            raise NoSuchLookingGlassObject(new_path_prefix,
                                                           second_segment)
                        if not isinstance(target, LookingGlassMixin):
                            LOG.error("Delegation target for '%s' at '%s' does"
                                      " not implement LookingGlassMixin (%s)!",
                                      second_segment, new_path_prefix,
                                      type(target))
                            raise NoSuchLookingGlassObject(new_path_prefix,
                                                           second_segment)
                        return target.get_looking_glass_info(newer_path_prefix,
                                                             path_reminder)
                    except KeyError:
                        raise NoSuchLookingGlassObject(new_path_prefix,
                                                       second_segment)

        # firt_segment is None or is not in our map
        # let's build LookingGlassLocalInfo
        info = self._get_log_local_info(path_prefix)
        for (path_item, (mapping_type, mapping_target)) in lg_map.iteritems():
            if path_item in info:
                LOG.warning("overriding '%s', present both in "
                            "LookingGlassLocalInfo and LookingGlassMixin map",
                            path_item)
            if mapping_type in (FORWARD, DELEGATE, SUBTREE, COLLECTION):
                info[path_item] = {"href": get_lg_prefixed_path(path_prefix,
                                                                [path_item])
                                   }
            elif mapping_type == SUBITEM:
                LOG.debug("   Subitem => callback %s(...)", mapping_target)
                # TODO: catch errors
                info[path_item] = mapping_target()
            elif mapping_type == VALUE:
                info[path_item] = mapping_target
            else:
                LOG.warning("LGMap not processed for %s", path_item)

        if first_segment is None:
            return info
        else:
            try:
                return _lookup_path(info, path)
            except KeyError as e:
                raise NoSuchLookingGlassObject(new_path_prefix, str(e))

        LOG.warning("Looking glass did not found a looking-glass object for"
                    " this path...")

        return None


class NoSuchLookingGlassObject(Exception):

    def __init__(self, path_prefix, path):
        Exception.__init__(self)
        assert isinstance(path_prefix, six.string_types)
        self.path_prefix = path_prefix

        assert isinstance(path, str)
        self.path = path

    def __repr__(self):
        return "No such looking glass object: %s at %s" % (self.path,
                                                           self.path_prefix)


# Looking glass reference URLs
root = ""
references = {}


def set_references_root(url_prefix):
    global root
    root = url_prefix


def set_reference_path(reference, path):
    references[reference] = path


def get_absolute_path(reference, path_prefix, path=None):
    if path is None:
        path = []
    index = path_prefix.find(root)
    absolute_base_url = path_prefix[:index + len(root)]
    return get_lg_prefixed_path(absolute_base_url,
                                references[reference] + path)


class LookingGlassLogHandler(python_logging.Handler):

    """
    This log handler simply stores the last <max_size> messages of importance
    above <level>. These messages can be retrieved with .get_records().
    """

    def __init__(self, level=logging.WARNING, max_size=100):
        python_logging.Handler.__init__(self, level)
        self.records = []
        self.max_size = max_size
        self.setFormatter(
            python_logging.Formatter('%(asctime)s - %(levelname)s - '
                                     '%(message)s'))

    def emit(self, record):
        # expand the log message now and free references to the arguments
        record.msg = record.getMessage().replace('"', "'")
        record.args = []
        self.records.insert(0, record)
        del self.records[self.max_size:]

    def __len__(self):
        return len(self.records)

    def get_records(self):
        return self.records

    def reset_local_lg_logs(self):
        del self.records[:]


class LookingGlassLocalLogger(LookingGlassMixin):

    """
    For objects subclassing this class, self.log will be a logger derived from
    <name> based on the existing logging configuration, but with an additional
    logger using LookingGlassLogHandler.

    This additional logger is used to make the last <n> records (above WARNING)
    available through the looking glass
    """

    def __init__(self, append_to_name=""):
        try:
            self.lg_log_handler
        except AttributeError:
            self.lg_log_handler = LookingGlassLogHandler()
            name = self.__module__  # + "." + self.__class__.__name__
            if append_to_name:
                name += "." + append_to_name
            elif hasattr(self, 'instance_id'):
                name += ".%d" % self.instance_id
            elif hasattr(self, 'name'):
                name += ".%s" % re.sub("[. ]", "-", self.name).lower()
            self.log = logging.getLogger(name)
            self.log.logger.addHandler(self.lg_log_handler)

    def get_lg_map(self):
        return {"logs": (SUBTREE, self.get_logs)}

    def get_logs(self, path_prefix):
        return [{'level': record.levelname,
                 'time': self.lg_log_handler.formatter.formatTime(record),
                 'message': record.msg}
                for record in self.lg_log_handler.get_records()]

    def _reset_local_lg_logs(self):
        self.lg_log_handler.reset_local_lg_logs()
