#!/usr/bin/env python

# Author: Harry Kodden

import tornado.httpserver
import tornado.ioloop
import tornado.web

import logging
from logging.handlers import SysLogHandler
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

from tornado.log import enable_pretty_logging
enable_pretty_logging()

from tornadows import soaphandler
from tornadows import webservices
from tornadows import xmltypes
from tornadows import complextypes
from tornadows.soaphandler import webservice
from tornado.options import define, options

from irods_support import irods_connect, irods_add_user, irods_add_group, irods_add_member, irods_remove_member, irods_get_members, irods_get_groups, irods_remove_group

from totp_auth import TotpAuth

import base64
import json

define('mode', default='deploy')
define('port', type=int, default=80)

cookie_location = "/tmp"

class cookie:
    def __init__(self, name, token):
        self.name = name
        self.token = token

    def verify(self):
        try:
            with open(cookie_location+"/"+self.name, "r") as f:
                if f.read() == self.token:
                    return True
        except:
            pass

        return False

    def touch(self):
        with open(cookie_location+"/"+self.name, "w") as f:
            f.write(self.token)

from ldap_support import ldap_get_password

class MySoapService(soaphandler.SoapHandler):

    @webservice(_params=[str, str], _returns=[str])
    def Authenticate(self, login, token):

        mycookie = cookie(login, token)
        if mycookie.verify():
            return "true"

        try:
            logger.info("Login request from: "+login)

            pwd = ldap_get_password(login)

            if TotpAuth(base64.b32encode(ldap_get_password(login))).valid(token):
                mycookie.touch()

                return "true"
            else:
                self.set_status(401)

        except Exception as e:
            self.set_status(500)
            logger.error("Exception during logon "+login+", error: "+str(e))

        return "false"

class BaseHandler(tornado.web.RequestHandler):

    def __init__(self, *args, **kwargs):
        self.username = None
        self.password = None
        self.hostname = "localhost"

        tornado.web.RequestHandler.__init__(self, *args, **kwargs)

    def prepare(self):
        self.my_response = ""

        logger.debug("REQUEST")
        logger.debug(str(self.request))
        logger.debug(str(self.request.headers))

        try:
            basic_auth = self.request.headers.get('Authorization')
            user_info = base64.decodestring(basic_auth[6:])
            self.username, self.password = user_info.split(':')

            logger.debug("USER: "+self.username)

            try:
                u, h = self.username.split('@')
                if h:
                    self.username = u
                    self.hostname = h
            except:
                pass

            logger.debug("USER: "+self.username)

            irods_connect(self.username, self.password, host=self.hostname)
        except:
            pass

        for k in self.request.arguments:
            logger.debug(k+': '+self.get_argument(k))

        try:
            logger.debug(json.dumps(json.loads(self.request.body), sort_keys=True, indent=4, separators=(',', ': ')))
        except:
            pass

    def write(self, data):
        self.my_response += data
        tornado.web.RequestHandler.write(self, data)

    def on_finish(self):
        logger.debug("RESPONSE")

        try:
            logger.debug(json.dumps(json.loads(self.my_response), sort_keys=True, indent=4, separators=(',', ': ')))
        except:
            pass

def irods_group(g):
    return g.replace(':', '-')

def grouper_group(g):
    return g.replace('-', ':')

class StemsHandler(BaseHandler):
    def delete(self, stem=None):

        if not stem:

            logger.debug("POST STEMS DELETE ERROR")

            self.set_status(400)
            self.set_header('X-Grouper-success', 'F')
            self.set_header('X-Grouper-resultCode', 'ERROR')
            self.set_header('X-Grouper-resultCode2', 'NONE')

        else:

            logger.debug("POST STEMS DELETE CALLED: ", stem)

            self.set_status(200)
            self.set_header('X-Grouper-success', 'T')
            self.set_header('X-Grouper-resultCode', 'SUCCESS')
            self.set_header('X-Grouper-resultCode2', 'NONE')

        self.content_type = 'application/json'

        self.write(json.dumps({
            "WsStemDeleteLiteResult": {
                "resultMetadata": {
                    "resultCode":"SUCCESS",
                        "success":"T"
                }
            }
        }))

    def post(self, stem=None):

        if stem:

            logger.debug("POST STEMS SAVE/UPDATE CALLED: ", stem)

            self.set_status(201)
            self.set_header('X-Grouper-success', 'T')
            self.set_header('X-Grouper-resultCode', 'SUCCESS')
            self.set_header('X-Grouper-resultCode2', 'NONE')

            self.content_type = 'application/json'

            self.write(json.dumps({
                "WsStemSaveLiteResult": {
                    "resultMetadata": {
                        "resultCode": "SUCCESS",
                            "success": "T"
                    }
                }
            }))

        else:

            logger.debug("POST STEMS GROUPER CALLED")

            data = json.loads(self.request.body)

            self.set_status(200)
            self.set_header('X-Grouper-success', 'T')
            self.set_header('X-Grouper-resultCode', 'SUCCESS')
            self.set_header('X-Grouper-resultCode2', 'NONE')

            self.content_type = 'application/json'

            self.write(json.dumps({
                "WsFindStemsResults": {
                    "resultMetadata": {
                        "resultCode": "SUCCESS",
                        "success": "T"
                    },
                    "stemResults":[
                        {
                            "name": data["WsRestFindStemsRequest"]["wsStemQueryFilter"]["stemName"]
                        }
                    ]
                }
            }))

class SubjectsHandler(BaseHandler):
    def post(self, subject=None):
        logger.debug("POST SUBJECTS GROUPER CALLED")

        wsGroups = []

        try:
            subjects = json.loads(self.request.body)["WsRestGetGroupsRequest"]["subjectLookups"]
            for s in subjects:
                logger.debug('COLLECT GROUPS FOR MEMBER: '+s["subjectId"])

                for g in irods_get_groups(s["subjectId"]):

                    wsGroups.append(
                        {
                            "name" : grouper_group(g)
                        }
                    )

        except Exception as e:
            logger.debug("Exception: %s" % str(e))

        self.set_status(201)
        self.set_header('X-Grouper-success', 'T')
        self.set_header('X-Grouper-resultCode', 'SUCCESS')
        self.set_header('X-Grouper-resultCode2', 'NONE')

        self.content_type = 'application/json'

        self.write(json.dumps({
            "WsGetGroupsResults":{
                "resultMetadata":{
                    "resultCode": "SUCCESS",
                    "success": "T"
                },
                "results":[
                    {
                        "wsGroups": wsGroups
                    }
                ]
            }
        }))

class GroupsHandler(BaseHandler):
    def get(self, name):
        logger.debug("GET GROUPS CALLED: "+name)

        self.set_status(200)
        self.set_header('X-Grouper-success', 'T')
        self.set_header('X-Grouper-resultCode', 'SUCCESS')
        self.set_header('X-Grouper-resultCode2', 'NONE')
        self.content_type = 'application/json'
        self.write('')

    def put(self, group, member = None):
        try:
            irods_add_group(irods_group(group))
            if member:

                logger.debug("PUT GROUPS CALLED: "+group+" MEMBER: "+member)

                irods_add_member(irods_group(group), member)

            try:
                data = json.loads(self.request.body)
                for m in data["WsRestAddMemberRequest"]["subjectLookups"]:
                    irods_add_user(m["subjectId"])
                    irods_add_member(irods_group(group), m["subjectId"])

            except Exception as e:
                    logger.error("Exception: %s" % str(e))


        except Exception as e:
            logger.error("Exception: %s" % str(e))

        self.set_header('X-Grouper-success', 'T')
        self.set_header('X-Grouper-resultCode', 'SUCCESS')
        self.set_header('X-Grouper-resultCode2', 'NONE')
        
        resultMetaData = {
            "resultCode" : "SUCCESS",
            "success" : "T"
        }

        self.set_status(201)
        self.content_type = 'application/json'

        if member:
            self.write(json.dumps( {
                "WsAddMemberLiteResults" : {
                    "resultMetadata" : resultMetaData
                }
            }))
        else:
            self.write(json.dumps({
                "WsAddMemberResults" : {
                    "resultMetadata" : resultMetaData
                }
            }))

    def delete(self, group, member = None):
        try:
            if member:
                logger.debug("DELETE GROUPS CALLED: "+group+" MEMBER: "+member)
                irods_remove_member(irods_group(group), member)
            else:
                logger.debug("DELETE GROUPS CALLED: "+group)
                irods_remove_group(irods_group(group))
        except Exception as e:
            logger.error("Exception: %s" % str(e))

        self.set_header('X-Grouper-success', 'T')
        self.set_header('X-Grouper-resultCode', 'SUCCESS')
        self.set_header('X-Grouper-resultCode2', 'NONE')
        resultMetaData = {
            "resultCode" : "SUCCESS",
            "success" : "T"
        }

        self.set_status(200)
        self.content_type = 'application/json'

        if member:
            self.write(json.dumps({
                "WsDeleteMemberLiteResult":{
                    "resultMetadata": resultMetaData
                }
            }))
        else:
            self.write(json.dumps({
                "WsGroupDeleteLiteResult":{
                    "resultMetadata": resultMetaData
                }
            }))

    def post(self, group=None):
        logger.debug("POST GROUPS GROUPER CALLED")

        self.set_status(200)
        self.set_header('X-Grouper-success', 'T')
        self.set_header('X-Grouper-resultCode', 'SUCCESS')
        self.set_header('X-Grouper-resultCode2', 'NONE')

        self.content_type = 'application/json'

        data = json.loads(self.request.body)

        try:
            groupResults = []

            if data["WsRestFindGroupsLiteRequest"]["queryFilterType"] == "FIND_BY_GROUP_NAME_EXACT":
                logger.debug("LOOKING FOR GROUP: "+data["WsRestFindGroupsLiteRequest"]["groupName"])

                if True: # if data["WsRestFindGroupsLiteRequest"]["groupName"] != ":":
                    groupResults.append(
                        {
                            "name": data["WsRestFindGroupsLiteRequest"]["groupName"]
                        }
                    )

            self.write(json.dumps({
                "WsFindGroupsResults": {
                    "resultMetadata": {
                        "resultCode": "SUCCESS",
                        "success": "T"
                    },
                    "groupResults": groupResults
                }
            }))

            return

        except:
            pass

        try:
            results = []

            for g in data["WsRestGetMembersRequest"]["wsGroupLookups"]:
                logger.debug("LOOKING FOR MEMBERS OF GROUP: '"+g["groupName"]+"'")

                subjects = []
                if True: #if g["groupName"] != ":":
                    n = 0;

                    try:
                        members = irods_get_members(irods_group(g["groupName"]))
                        members.sort()

                        for m in members:
                            n = n + 1

                            if n < ((data["WsRestGetMembersRequest"]["pageNumber"] -1) * data["WsRestGetMembersRequest"]["pageSize"]):
                                continue

                            subjects.append({ "id": m })

                            if (n % data["WsRestGetMembersRequest"]["pageSize"]) == 0:
                                break

                    except Exception as e:
                        logger.error("Exception: %s" % str(e))

                    results.append( {
                        "wsGroup": {
                            "name": g["groupName"]
                        },
                            "wsSubjects": subjects
                        }
                    )

                    self.write(json.dumps({
                        "WsGetMembersResults": {
                             "resultMetadata": {
                                "resultCode": "SUCCESS",
                                "success": "T"
                             },
                            "results": results
                        }
                    }))

                    return
        except:
            pass

        try:
            g = data["WsRestGroupSaveLiteRequest"]["groupName"]
            if g != ":":
                irods_add_group(irods_group(g))

                logger.debug(json.dumps(json.loads(self.request.body), sort_keys=True, indent=4, separators=(',', ': ')))

            self.set_status(201)
            self.write(json.dumps({
                "WsGroupSaveLiteResult":{
                    "resultMetadata":{
                        "resultCode":"SUCCESS_INSERTED",
                        "success":"T"
                    },
                    "wsGroup": {
                        "name": g
                    }
                }
            }))

            return
        except:
            pass

        try:
            for s in  data["WsRestDeleteMemberRequest"]["subjectLookups"]:
                irods_remove_member(irods_group(group), s["subjectId"])

            self.write(json.dumps({
                "WsDeleteMemberResults":{
                    "resultMetadata":{
                        "resultCode": "SUCCESS",
                        "success": "T"
                    }
                }
            }))

            return
        except Exception as e:
            pass

        logger.debug("Undefined Request !")
        logger.debug(json.dumps(json.loads(self.request.body), sort_keys=True, indent=4, separators=(',', ': ')))

# We both Serve 'SOAP' endpoint as well as RESTfull Entpoints...

if __name__ == '__main__':
   service = [
    ('api', MySoapService),
    ('api/servicesRest/v2_1_000/stems', StemsHandler),
    ('api/servicesRest/v2_1_000/stems/(.*)', StemsHandler),
    ('api/servicesRest/v2_1_000/subjects', SubjectsHandler),
    ('api/servicesRest/v2_1_000/subjects/(.*)', SubjectsHandler),
    ('api/servicesRest/v2_1_000/groups', GroupsHandler),
    ('api/servicesRest/v2_1_000/groups/(.*)/members/(.*)', GroupsHandler),
    ('api/servicesRest/v2_1_000/groups/(.*)/members', GroupsHandler),
    ('api/servicesRest/v2_1_000/groups/(.*)', GroupsHandler),
   ]

   logger.info('Processing started')

   ws = webservices.WebService(service)
   application = tornado.httpserver.HTTPServer(ws)
   application.listen(options.port)
   tornado.ioloop.IOLoop.instance().start()
