#!/usr/bin/env python

import six
if six.PY3:
    from html import escape
else:
    from cgi import escape

from irods.models import User, UserGroup
from irods.manager import Manager
from irods.message import GeneralAdminRequest, iRODSMessage
from irods.exception import UserDoesNotExist, UserGroupDoesNotExist, NoResultFound
from irods.api_number import api_number
from irods.user import iRODSUser, iRODSUserGroup
import irods.password_obfuscation as obf

import logging
from logging.handlers import SysLogHandler
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

from irods.session import iRODSSession
from irods.models import Collection, User, DataObject

my_irods_host = None
my_irods_port = None
my_irods_zone = None
my_irods_user = None
my_irods_pass = None
my_irods_sess = None

DEFAULT_PORT = 1247
DEFAULT_ZONE = "tempZone"

def _session():
    global my_irods_host
    global my_irods_port
    global my_irods_zone
    global my_irods_user
    global my_irods_pass
    global my_irods_sess

    if not my_irods_sess:
       try:
           logger.info("IRODS: Establishing session...")
           my_irods_sess = iRODSSession(host=my_irods_host, port=my_irods_port, user=my_irods_user, password=my_irods_pass, zone=my_irods_zone)
           if my_irods_sess:
                logger.debug("We are connected to : "+my_irods_host)
       except Exception as e:
           logger.debug("Connection problem: "+str(e))

    return my_irods_sess

def irods_connect(usr, pwd, host = 'localhost', port = DEFAULT_PORT, zone = DEFAULT_ZONE):
    global my_irods_host
    global my_irods_port
    global my_irods_zone
    global my_irods_user
    global my_irods_pass
    global my_irods_sess

    try:
       if my_irods_host == host and my_irods_port == port and my_irods_zone == zone and my_irods_user == usr and my_irods_pass == pwd:
          logger.debug("Reusing existing session to: "+my_irods_host)
          return

    except:
       logger.debug("Closing session...")
       my_irods_sess = None

    my_irods_host = host
    my_irods_port = port
    my_irods_zone = zone
    my_irods_user = usr
    my_irods_pass = pwd

    _session()

class UserManager(Manager):

    def get(self, user_name, user_zone=""):
        query = self.sess.query(User).filter(User.name == user_name)

        if len(user_zone) > 0:
            query = query.filter(User.zone == user_zone)

        try:
            result = query.one()
        except NoResultFound:
            raise UserDoesNotExist()
        return iRODSUser(self, result)

    def groups(self, user_name):
        for result in self.sess.query(UserGroup).filter(User.name == user_name).get_results():
            yield self.sess.user_groups.get(result[UserGroup.name])

    def create(self, user_name, user_type, user_zone="", auth_str=""):
        message_body = GeneralAdminRequest(
            "add",
            "user",
            user_name,
            user_type,
            user_zone,
            auth_str
        )
        request = iRODSMessage("RODS_API_REQ", msg=message_body,
                               int_info=api_number['GENERAL_ADMIN_AN'])
        with self.sess.pool.get_connection() as conn:
            conn.send(request)
            response = conn.recv()
        logger.debug(response.int_info)
        return self.get(user_name, user_zone)

    def remove(self, user_name, user_zone=""):
        message_body = GeneralAdminRequest(
            "rm",
            "user",
            user_name,
            user_zone
        )
        request = iRODSMessage("RODS_API_REQ", msg=message_body,
                               int_info=api_number['GENERAL_ADMIN_AN'])
        with self.sess.pool.get_connection() as conn:
            conn.send(request)
            response = conn.recv()
        logger.debug(response.int_info)

    def modify(self, user_name, option, new_value, user_zone=""):

        # must append zone to username for this API call
        if len(user_zone) > 0:
            user_name += "#" + user_zone

        with self.sess.pool.get_connection() as conn:

            # if modifying password, new value needs obfuscating
            if option == 'password':
                current_password = self.sess.pool.account.password
                new_value = obf.obfuscate_new_password(new_value, current_password, conn.client_signature)

                # html style escaping might have to be generalized:
                # https://github.com/irods/irods/blob/4.2.1/lib/core/src/packStruct.cpp#L1913
                # https://github.com/irods/irods/blob/4.2.1/lib/core/src/packStruct.cpp#L1331-L1368
                new_value = escape(new_value, quote=False)

            message_body = GeneralAdminRequest(
                "modify",
                "user",
                user_name,
                option,
                new_value,
                user_zone,
            )
            request = iRODSMessage("RODS_API_REQ", msg=message_body,
                                   int_info=api_number['GENERAL_ADMIN_AN'])

            conn.send(request)
            response = conn.recv()
        logger.debug(response.int_info)


class UserGroupManager(UserManager):

    def get(self, name, user_zone=""):
        query = self.sess.query(UserGroup).filter(UserGroup.name == name)

        try:
            result = query.one()
        except NoResultFound:
            raise UserGroupDoesNotExist()

        return iRODSUserGroup(self, result)

    def create(self, name, user_type='rodsgroup', user_zone="", auth_str=""):
        message_body = GeneralAdminRequest(
            "add",
            "user",
            name,
            user_type,
            "",
            ""
        )
        request = iRODSMessage("RODS_API_REQ", msg=message_body,
                               int_info=api_number['GENERAL_ADMIN_AN'])
        with self.sess.pool.get_connection() as conn:
            conn.send(request)
            response = conn.recv()
        logger.debug(response.int_info)
        return self.get(name)

    def getmembers(self, name):
        results = self.sess.query(User).filter(
            User.type != 'rodsgroup', UserGroup.name == name).get_results()
        return [iRODSUser(self, row) for row in results]

    def addmember(self, group_name, user_name, user_zone=""):
        message_body = GeneralAdminRequest(
            "modify",
            "group",
            group_name,
            "add",
            user_name,
            user_zone
        )
        request = iRODSMessage("RODS_API_REQ", msg=message_body,
                               int_info=api_number['GENERAL_ADMIN_AN'])
        with self.sess.pool.get_connection() as conn:
            conn.send(request)
            response = conn.recv()
        logger.debug(response.int_info)

    def removemember(self, group_name, user_name, user_zone=""):
        message_body = GeneralAdminRequest(
            "modify",
            "group",
            group_name,
            "remove",
            user_name,
            user_zone
        )
        request = iRODSMessage("RODS_API_REQ", msg=message_body,
                               int_info=api_number['GENERAL_ADMIN_AN'])
        with self.sess.pool.get_connection() as conn:
            conn.send(request)
            response = conn.recv()
        logger.debug(response.int_info)


# Public endtrypoints

def irods_add_user(username):
    logger.debug("IRODS: ADD USER: "+username)

    try:
       u = UserManager(_session())
       u.create(username, 'rodsuser', user_zone = DEFAULT_ZONE)
    except Exception as e:
       #logger.debug("IRODS: Error during add user (%s)" % str(e))
       pass

def irods_add_group(groupname):
    logger.debug("IRODS: ADD GROUP: "+groupname)

    try:
       g = UserGroupManager(_session())
       g.create(groupname, user_zone = DEFAULT_ZONE)
    except Exception as e:
       #logger.debug("IRODS: Error during add group (%s)" % str(e))
       pass

def irods_remove_group(groupname):
    logger.debug("IRODS: REMOVE GROUP: "+groupname)

    try:
       for m in irods_get_members(groupname):
          irods_remove_member(groupname, m, user_zone = DEFAULT_ZONE)
    except:
       pass

    logger.debug("... WE DO NOT DO THIS AT THE MOMENT ...")
    return

    try:
       g = UserGroupManager(_session())
       g.remove(groupname, user_zone = DEFAULT_ZONE)
    except Exception as e:
       logger.debug("IRODS: Error during remove group (%s)" % str(e))
       pass

def irods_add_member(groupname, username):
    logger.debug("IRODS: ADD MEMBER: "+username+" TO GROUP: "+groupname)

    try:
       # make sure the user exists...
       irods_add_user(username)
    except:
       pass

    try:
       # make sure the group exists...
       irods_add_group(groupname)
    except:
       pass

    try:
       g = UserGroupManager(_session())
       g.addmember(groupname, username, user_zone = DEFAULT_ZONE)
    except Exception as e:
       logger.debug("IRODS: Error during add member (%s)" % str(e))
       pass

def irods_remove_member(groupname, username):
    logger.debug("IRODS: REMOVE MEMBER: "+username+" OF GROUP: "+groupname)

    try:
       g = UserGroupManager(_session())
       g.removemember(groupname, username, user_zone = DEFAULT_ZONE)
    except Exception as e:
       logger.debug("IRODS: Error during remove member (%s)" % str(e))
       pass

def irods_get_groups(username):
    logger.debug("IRODS: GET GROUPS OF USER: "+username)

    result = []

    try:
       g = UserGroupManager(_session())
       l = g.groups(username)

       logger.debug("IRODS USER: "+username)
       for g in l:
          logger.debug(" IRODS GROUP: "+str(g.name))
          result.append(g.name)

    except Exception as e:
       logger.debug("IRODS: Error during get groups (%s)" % str(e))

    return result

def irods_get_members(groupname):
    logger.debug("IRODS: GET MEMBERS OF GROUP: "+groupname)

    result = []

    try:
       g = UserGroupManager(_session())
       l = g.getmembers(groupname)

       logger.debug("IRODS GROUP: "+groupname)
       for m in l:
          logger.debug(" IRODS MEMBER: "+str(m.name))
          result.append(m.name)

    except Exception as e:
       logger.debug("IRODS: Error during get members (%s)" % str(e))

    return result

