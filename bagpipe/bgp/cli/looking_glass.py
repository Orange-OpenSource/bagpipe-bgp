#!/usr/bin/env python
#
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

from sys import stdout

import os
import urllib2
import json

from optparse import OptionParser

BAGPIPE_PORT = 8082
LOOKING_GLASS_BASE = "looking-glass"

INDENT_INCREMENT = 2


def pretty_print_recurse(data, indent=0, alreadyANewLine=False):
    """
    key has already been output, this function will print data and finish at
    a start of line

    returns True if the key output was spread across multiple lines.
    """
    if isinstance(data, dict):
        more = False

        if ("id" in data and "href" in data):
            stdout.write(data["id"])
            del data["id"]

        if ("href" in data):
            del data["href"]
            more = True

        if more:
            stdout.write(" (...)")
            alreadyANewLine = False

        if len(data) > 0:
            if not alreadyANewLine:
                stdout.write("\n")
            firstVal = True
            for (key, value) in data.iteritems():
                if not firstVal or not alreadyANewLine:
                    stdout.write("%s" % (" " * indent))
                if firstVal:
                    firstVal = False
                stdout.write("%s: " % key)
                pretty_print_recurse(value, indent + INDENT_INCREMENT)
        else:
            if more:
                stdout.write("\n")
            else:
                stdout.write("-\n")

    elif isinstance(data, list):

        if len(data) > 0:
            if not alreadyANewLine:
                stdout.write("\n")
                alreadyANewLine = True

            for i in range(len(data)):
                value = data[i]
                stdout.write("%s* " % (" " * indent))
                if isinstance(value, dict) or isinstance(value, list):
                    pretty_print_recurse(
                        value, indent + INDENT_INCREMENT, alreadyANewLine)
                else:
                    stdout.write("%s\n" % value)
                alreadyANewLine = True
        else:
            stdout.write("-\n")

    else:
        if isinstance(data, str) and "\n" in data:
            data = data.strip("\n").replace("\n", "\n%s" % (" " * indent))
            stdout.write("\n%s" % (" " * indent))

        stdout.write("%s\n" % data)
        return False


def main():
    usage = """ %prog [--server <ip>] path to object in looking-glass

e.g.: %prog vpns instances"""
    parser = OptionParser(usage)

    parser.add_option(
        "--server", dest="server",
        help="IP address of BaGPipe BGP (optional, default: %default)",
        default="127.0.0.1")

    (options, args) = parser.parse_args()

    quoted_args = [urllib2.quote(arg) for arg in args]

    target_url = "http://%s:%d/%s/%s" % (options.server, BAGPIPE_PORT,
                                         LOOKING_GLASS_BASE,
                                         "/".join(quoted_args))
    try:
        os.environ['NO_PROXY'] = options.server
        response = urllib2.urlopen(target_url)
    except urllib2.HTTPError as e:
        if e.code == 404:
            print "No such looking glass path: %s\n(%s)" % (
                " ".join(quoted_args),
                target_url)
        else:
            print "Error code %d: %s" % (e.getcode(), e.read())
        return

    if response.getcode() == 200:
        data = json.load(response)
        pretty_print_recurse(data, indent=0, alreadyANewLine=True)
