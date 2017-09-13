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

import logging

import re

import urllib

from bagpipe.bgp.common.utils import enum

log = logging.getLogger(__name__)

LGMap = enum('VALUE', 'SUBITEM', 'SUBTREE',
             'FORWARD', 'COLLECTION', 'DELEGATE')


def _splitLGPath(pathPrefix, path):
    if len(path) == 0:
        return (None, None, pathPrefix)
    else:
        return (path[0], path[1:],
                "%s/%s" % (pathPrefix, urllib.quote(path[0])))


def _getLGLocalInfoRecurse(obj, cls, pathPrefix):

    if cls == LookingGlass:
        return {}

    log.debug("_getLGLocalInfoRecurse: %s", cls)

    result = cls.getLookingGlassLocalInfo(obj, pathPrefix)

    assert(isinstance(result, dict))

    for base in cls.__bases__:
        if issubclass(base, LookingGlass):
            result.update(
                _getLGLocalInfoRecurse(obj, base, pathPrefix))

    return result


def _getLGMapRecurse(obj, cls):

    if cls == LookingGlass:
        return {}

    log.debug("_getLGMapRecurse: %s", cls)

    result = cls.getLGMap(obj)

    for base in cls.__bases__:
        if issubclass(base, LookingGlass):
            result.update(_getLGMapRecurse(obj, base))
        else:
            log.debug("not recursing into %s", base)

    return result


def _lookupPathInDict(myDict, path):

    log.debug("_lookupPathInDict: %s vs. %s", myDict, path)

    assert(isinstance(path, list))

    if len(path) == 0:
        log.debug("path len is zero, returning myDict %s", myDict)
        return myDict

    # len(path)>0
    if not (isinstance(myDict, dict)):
        raise KeyError(path[0])
    else:
        return _lookupPathInDict(myDict[path[0]], path[1:])


class LookingGlass(object):

    def _getLGMap(self):
        """not to be overridden: calls getLGMap, on each of the super classes
           and merge the result in a dict
        """
        return _getLGMapRecurse(self, self.__class__)

    def getLGMap(self):
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
            calling hook(pathPrefix), but this information will only be
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
            functions (listCallback,targetCallback). listCallback() is expected
            to return a list of string, each string identifying a looking
            glass object targetCallback(string) is expected to return the
            looking glass object corresponding to <string>

            if *self* is directly queried, the information returned is just a
            list of dict containing "href" values pointing to each object in
            the collection
            if a <subpath> is queried, the information returned is the
            looking glass information for the object corresponding to
            <subpath>
        """
        return {}

    def _getLookingGlassLocalInfo(self, pathPrefix):
        """
        not to be overridden: calls getLookingGlassLocalInfo, on each of
          the super classes and merge the result in a dict
        """
        return _getLGLocalInfoRecurse(self, self.__class__, pathPrefix)

    def getLookingGlassLocalInfo(self, pathPrefix):
        """
        Can be overriden by looking glass objects.

        :param pathPrefix: the URL prefix that was used to reach *self*
            through the looking glass
        :returns: a dict that will be serialized as JSON and passed to the
            looking glass client, either as is, or if a sub path was queried,
            the dict value corresponding to the first item of the path
        """
        return {}

    def getLookingGlassInfo(self, pathPrefix="", path=None):
        """
        This method builds the looking glass information for *self* based on
        the looking glass map

        *not* to be overridden by looking glass objects
        """
        if path is None:
            path = []

        (firstSegment, restOfPath,
         newPathPrefix) = _splitLGPath(pathPrefix, path)

        lgMap = self._getLGMap()

        if (firstSegment in lgMap):
            (mappingType, mappingTarget) = lgMap[firstSegment]
            log.debug("Delegation for pathItem '%s': %s:%s ",
                      firstSegment, LGMap.reverse[mappingType], mappingTarget)

            if mappingType == LGMap.VALUE:
                return mappingTarget

            if mappingType == LGMap.FORWARD:
                log.debug(
                    "   Forwarded '%s' to target %s...", path, mappingTarget)
                if not isinstance(mappingTarget, LookingGlass):
                    log.error(
                        "Delegation target for '%s' at '%s' does not "
                        "implement LookingGlass!", firstSegment, newPathPrefix)
                    raise NoSuchLookingGlassObject(
                        newPathPrefix, firstSegment)
                return mappingTarget.getLookingGlassInfo(pathPrefix, path)

            if mappingType == LGMap.FORWARD:
                log.debug(
                    "   Forwarded '%s' to target %s...", path, mappingTarget)
                if not isinstance(mappingTarget, LookingGlass):
                    log.error(
                        "Delegation target for '%s' at '%s' does not "
                        "implement LookingGlass!", firstSegment, newPathPrefix)
                    raise NoSuchLookingGlassObject(newPathPrefix, firstSegment)
                return mappingTarget.getLookingGlassInfo(pathPrefix, path)

            elif mappingType == LGMap.DELEGATE:
                log.debug(
                    "   Delegated '%s' to delegation target %s ...",
                    path, mappingTarget)
                if not isinstance(mappingTarget, LookingGlass):
                    log.error(
                        "Delegation target for '%s' at '%s' does not "
                        "implement LookingGlass!", firstSegment, newPathPrefix)
                    raise NoSuchLookingGlassObject(newPathPrefix, firstSegment)
                return mappingTarget.getLookingGlassInfo(newPathPrefix,
                                                         restOfPath)

            elif mappingType == LGMap.SUBITEM:
                log.debug("   Sub-item callback: %s", firstSegment)
                try:
                    return _lookupPathInDict(mappingTarget(), restOfPath)
                except KeyError as e:
                    raise NoSuchLookingGlassObject(newPathPrefix, str(e))

            elif mappingType == LGMap.SUBTREE:
                log.debug("   Subtree callback: %s(...)", firstSegment)
                try:
                    return _lookupPathInDict(mappingTarget(newPathPrefix),
                                             restOfPath)
                except KeyError as e:
                    raise NoSuchLookingGlassObject(newPathPrefix, str(e))

            elif mappingType == LGMap.COLLECTION:
                log.debug("   Collection callback...")

                (listCallback, targetCallback) = mappingTarget

                (secondSegment, restOfPath, newerPathPrefix) = \
                    _splitLGPath(newPathPrefix, restOfPath)
                if secondSegment is None:
                    log.debug("   Getting list elements: %s", listCallback)
                    result = []
                    for x in listCallback():
                        x["href"] = LookingGlass.getLGPrefixedPath(
                            pathPrefix, [firstSegment, x["id"]])
                        result.append(x)
                    return result
                else:
                    log.debug("   Callback -> resolve subItem '%s' with %s "
                              "and follow up getLookingGlassInfo(...'%s')",
                              secondSegment, targetCallback, restOfPath)
                    try:
                        target = targetCallback(secondSegment)
                        if target is None:
                            log.error("No delegation target for '%s' at '%s' ",
                                      secondSegment, newPathPrefix)
                            raise NoSuchLookingGlassObject(
                                newPathPrefix, secondSegment)
                        if not isinstance(target, LookingGlass):
                            log.error("Delegation target for '%s' at '%s' "
                                      "does not implement LookingGlass (%s)!",
                                      secondSegment, newPathPrefix,
                                      type(target))
                            raise NoSuchLookingGlassObject(
                                newPathPrefix, secondSegment)
                        return target.getLookingGlassInfo(newerPathPrefix,
                                                          restOfPath)
                    except KeyError:
                        raise NoSuchLookingGlassObject(
                            newPathPrefix, secondSegment)

        # firtSegment is None or is not in our map
        # let's build LookingGlassLocalInfo
        info = self._getLookingGlassLocalInfo(pathPrefix)
        for (pathItem, (mappingType, mappingTarget)) in lgMap.iteritems():
            if pathItem in info:
                log.warning("overriding '%s', present both in "
                            "LookingGlassLocalInfo and LookingGlass map",
                            pathItem)
            if mappingType in (LGMap.FORWARD, LGMap.DELEGATE, LGMap.SUBTREE,
                               LGMap.COLLECTION):
                info[pathItem] = {"href":
                                  LookingGlass.getLGPrefixedPath(pathPrefix,
                                                                 [pathItem])}
            elif mappingType == LGMap.SUBITEM:
                log.debug("   Subitem => callback %s(...)", mappingTarget)
                info[pathItem] = mappingTarget()
            elif mappingType == LGMap.VALUE:
                info[pathItem] = mappingTarget
            else:
                log.warning("LGMap not processed for %s", pathItem)

        if firstSegment is None:
            return info
        else:
            try:
                return _lookupPathInDict(info, path)
            except KeyError as e:
                raise NoSuchLookingGlassObject(newPathPrefix, str(e))

        log.warning("Looking glass did not found a looking-glass object for"
                    " this path...")

        return None

    @staticmethod
    def getLGPrefixedPath(pathPrefix, pathItems):
        fmt = "%s" + ('/%s' * len(pathItems))
        quotedPathItems = [urllib.quote(pathItem) for pathItem in pathItems]
        quotedPathItems.insert(0, pathPrefix)
        return fmt % tuple(quotedPathItems)


class NoSuchLookingGlassObject(Exception):

    def __init__(self, pathPrefix, path):
        Exception.__init__(self)
        assert(isinstance(pathPrefix, str))
        self.pathPrefix = pathPrefix

        assert(isinstance(path, str))
        self.path = path

    def __repr__(self):
        return "No such looking glass object: %s at %s" % (self.path,
                                                           self.pathPrefix)


class LookingGlassReferences(object):

    root = ""
    references = {}

    @staticmethod
    def setRoot(urlPrefix):
        LookingGlassReferences.root = urlPrefix

    @staticmethod
    def setReferencePath(reference, path):
        LookingGlassReferences.references[reference] = path

    @staticmethod
    def getAbsolutePath(reference, pathPrefix, path=None):
        if path is None:
            path = []
        index = pathPrefix.find(LookingGlassReferences.root)
        absoluteBaseURL = pathPrefix[:index + len(LookingGlassReferences.root)]
        return LookingGlass.getLGPrefixedPath(
            absoluteBaseURL,
            LookingGlassReferences.references[reference] + path)


class LookingGlassLogHandler(logging.Handler):

    """
    This log handler simply stores the last <maxSize> messages of importance
    above <level>. These messages can be retrieved with .getRecords().
    """

    def __init__(self, level=logging.WARNING, maxSize=100):
        logging.Handler.__init__(self, level)
        self.records = []
        self.maxSize = maxSize
        self.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))

    def emit(self, record):
        # expand the log message now and free references to the arguments
        record.msg = record.getMessage().replace('"', "'")
        record.args = None
        self.records.insert(0, record)
        del self.records[self.maxSize:]

    def __len__(self):
        return len(self.records)

    def getRecords(self):
        return self.records

    def resetLocalLGLogs(self):
        del self.records[:]


class LookingGlassLocalLogger(LookingGlass):

    """
    For objects subclassing this class, self.log will be a logger derived from
    <name> based on the existing logging configuration, but with an additional
    logger using LookingGlassLogHandler.

    This additional logger is used to make the last <n> records (above WARNING)
    available through the looking glass
    """

    def __init__(self, appendToName=""):
        try:
            self.lgLogHandler
        except AttributeError:
            self.lgLogHandler = LookingGlassLogHandler()
            name = self.__module__  # + "." + self.__class__.__name__
            if appendToName:
                name += "." + appendToName
            elif (hasattr(self, 'instanceId')):
                name += ".%d" % self.instanceId
            elif (hasattr(self, 'name')):
                name += ".%s" % re.sub("[. ]", "-", self.name).lower()
            self.log = logging.getLogger(name)
            self.log.addHandler(self.lgLogHandler)

    def getLGMap(self):
        return {"logs": (LGMap.SUBTREE, self.getLogs)}

    def getLogs(self, pathPrefix):
        return [{'level': record.levelname,
                 'time': self.lgLogHandler.formatter.formatTime(record),
                 'message': record.msg}
                for record in self.lgLogHandler.getRecords()]

    def _resetLocalLGLogs(self):
        self.lgLogHandler.resetLocalLGLogs()
