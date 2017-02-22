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

import os
from sys import stdout

import optparse
from oslo_serialization import jsonutils
import urllib2


BAGPIPE_PORT = 8082
LOOKING_GLASS_BASE = "looking-glass"

INDENT_INCREMENT = 2


def pretty_print_recurse(data, indent, recursive_requests, url,
                         already_anew_line=False):
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
            more = True

        if more:
            target_url = data["href"]
            if recursive_requests:
                if target_url.startswith(url):
                    response = urllib2.urlopen(target_url)
                    if response.getcode() == 200:
                        pretty_print_recurse(jsonutils.load(response),
                                             indent + INDENT_INCREMENT,
                                             recursive_requests, target_url,
                                             already_anew_line=False)
                        return True
                    else:
                        stdout.write(" (ERROR %d)", response.getcode())
                        return False

            del data["href"]
            stdout.write(" (...)")
            already_anew_line = False

        if len(data) > 0:
            if not already_anew_line:
                stdout.write("\n")
            first_val = True
            for (key, value) in data.iteritems():
                if not first_val or not already_anew_line:
                    stdout.write("%s" % (" " * indent))
                if first_val:
                    first_val = False
                stdout.write("%s: " % key)
                pretty_print_recurse(value, indent + INDENT_INCREMENT,
                                     recursive_requests, url)
        else:
            if more:
                stdout.write("\n")
            else:
                stdout.write("-\n")

    elif isinstance(data, list):

        if len(data) > 0:
            if not already_anew_line:
                stdout.write("\n")
                already_anew_line = True

            for value in data:
                stdout.write("%s* " % (" " * indent))
                if isinstance(value, dict) or isinstance(value, list):
                    pretty_print_recurse(value, indent + INDENT_INCREMENT,
                                         recursive_requests, url,
                                         already_anew_line)
                else:
                    stdout.write("%s\n" % value)
                already_anew_line = True
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
    parser = optparse.OptionParser(usage)

    parser.add_option(
        "--server", dest="server", default="127.0.0.1",
        help="IP address of BaGPipe BGP (optional, default: %default)")

    parser.add_option(
        "--port", dest="port", type="int", default=BAGPIPE_PORT,
        help="Port of BaGPipe BGP (optional, default: %default)")

    parser.add_option(
        "--prefix", dest="prefix", default=LOOKING_GLASS_BASE,
        help="Looking-glass URL Prefix (optional, default: %default)")

    parser.add_option(
        "-r", "--recurse", dest="recurse", action="store_true", default=False,
        help="Recurse down into the whole looking-glass (disabled by default)")

    (options, args) = parser.parse_args()

    quoted_args = [urllib2.quote(arg) for arg in args]
    target_url = "http://%s:%d/%s/%s" % (options.server, options.port,
                                         options.prefix, "/".join(quoted_args))
    try:
        os.environ['NO_PROXY'] = options.server
        response = urllib2.urlopen(target_url)

        if response.getcode() == 200:
            data = jsonutils.load(response)

            if (isinstance(data, dict) and "href" in data):
                target_url_bis = data["href"]
                response_bis = urllib2.urlopen(target_url_bis)
                if response.getcode() == 200:
                    target_url = target_url_bis
                    data = jsonutils.load(response_bis)

            pretty_print_recurse(data, 0, options.recurse, target_url,
                                 already_anew_line=True)

    except urllib2.HTTPError as e:
        if e.code == 404:
            print "No such looking glass path: %s\n(%s)" % (
                " ".join(quoted_args), target_url)
        else:
            print "Error code %d: %s" % (e.getcode(), e.read())
        return
    except urllib2.URLError as e:
        print "No server at http://%s:%d : %s" % (options.server,
                                                  options.port, e)
