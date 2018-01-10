#!/usr/bin/env python

import os
import ldap
import ldap.modlist as modlist

import logging
from logging.handlers import SysLogHandler
logger = logging.getLogger()
logger.setLevel(logging.ERROR)

ldap_manager = 'admin'
ldap_password  = os.environ['LDAP_PASSWORD']

def ldap_domain():
    dc = ''
    for sub in os.environ['LDAP_DOMAIN'].split('.'):
       if len(dc) > 0:
          dc += ','
       dc += 'dc='+sub

    return dc

def _ldap(dn, operation, ldif = None, searchScope = None, searchFilter = None, retrieveAttributes = None):
    l = ldap.initialize("ldap://"+os.environ['LDAP_HOST']+":389/")

    l.simple_bind_s("cn="+ldap_manager+","+ldap_domain(), ldap_password)

    result = None
    try:
       if operation == 'ADD':
          l.add_s(dn, ldif)
       elif operation == 'MODIFY':
          l.modify_s(dn, ldif)
       elif operation == 'DELETE':
          l.delete_s(dn)
       elif operation == 'SEARCH':
          result_set = []

          ldap_result_id = l.search(dn, searchScope, searchFilter, retrieveAttributes)
          while 1:
             result_type, result_data = l.result(ldap_result_id, 0)
             if (result_data == []):
                break
             else:
                if result_type == ldap.RES_SEARCH_ENTRY:
                   result_set.append(result_data)

          result = result_set
 
    except ldap.LDAPError, e:
       result = None
       logger.error(str(e))

    l.unbind_s()

#   if (result):
#      for r in result:
#         logger.debug(str(r))
#
    return result

def ldap_update(dn, old, new):
    ldif = ldap.modlist.modifyModlist(old,new)
    _ldap(dn, 'MODIFY', ldif = ldif)
    
def ldap_delete(dn):
    _ldap(dn, 'DELETE')
    
import hashlib
from base64 import urlsafe_b64encode as encode
from base64 import urlsafe_b64decode as decode

def ldap_make_password(password):
    salt = os.urandom(4)
    h = hashlib.sha1(password)
    h.update(salt)
    return "{SSHA}" + encode(h.digest() + salt)

def ldap_check_password(username, password):
    try:
       challenge_password = ldap_get_password(username)
       challenge_bytes = decode(challenge_password[6:])
       digest = challenge_bytes[:20]
       salt = challenge_bytes[20:]
       hr = hashlib.sha1(password)
       hr.update(salt)
       return digest == hr.digest()
    except:
       return False

def ldap_add_user(username, password, firstname='', lastname=''):
    dn = "uid="+username+",ou=people,"+ldap_domain()

    attrs = {}
    attrs['cn'] = str(username)
    attrs['givenname'] = str(firstname)
    attrs['mail'] = str(username)
    attrs['objectclass'] = ['top','inetOrgPerson']
    attrs['sn'] = str(lastname)
    attrs['uid'] = str(username)
    attrs['userPassword'] = str(ldap_make_password(password))
    attrs['description'] = []

    ldif = modlist.addModlist(attrs)

    _ldap(dn, 'ADD', ldif = ldif)

def ldap_add_attribute(username, attribute, value):
    dn = "uid="+username+",ou=people,"+ldap_domain()
    ldap_update(dn, { attribute: ''} , { attribute: str(value) })

def ldap_add_member(group, member):
    dn = "ou="+group+",ou=groups,"+ldap_domain()

    try:
      ldap_update(dn, { 'member':'' }, { 'member': str("uid="+member+",ou=people,"+ldap_domain()) })
    except:
      logger.error("Failed to add member: "+member+" to group: "+group)

def ldap_remove_member(group, member):
    m = ldap_search('ou='+group+',ou=groups,'+ldap_domain(), searchFilter = "member=*", retrieveAttributes = ['member'])
    m_new = []
    try:
      m_old = m[0][0][1]['member']

      for i in range(0,len(m_old)):
        if ldap_name(m_old[i]) != member:
           m_new.append(m_old[i])

      ldap_update('ou='+group+',ou=groups,'+ldap_domain(), { 'member':m_old }, { 'member':m_new })
    except:
      logger.error("Failed to remove member: "+member+" from group: "+group)
    
def ldap_add_manager(group, manager):
    dn = "ou="+group+",ou=groups,"+ldap_domain()

    try:
      ldap_update("uid="+manager+",ou=people,"+ldap_domain(), { 'manager':'' }, { 'manager': str(dn) })
    except:
      logger.error("Failed to add manager: "+manager+" to group: "+group)

def ldap_add_group(group):
    dn = "ou="+group+",ou=groups,"+ldap_domain()

    attrs = {}
    attrs['ou'] = str(group)
    attrs['objectclass'] = ['top','organizationalUnit', 'extensibleObject']

    try:
      ldif = modlist.addModlist(attrs)
      _ldap(dn, 'ADD', ldif = ldif)
    except:
      logger.error("Failed to add group: "+group)\

def ldap_search(dn, searchScope = ldap.SCOPE_SUBTREE, searchFilter = "uid=*", retrieveAttributes = ['cn', 'givenname', 'manager']):
    return _ldap(dn, "SEARCH", searchScope=searchScope, searchFilter=searchFilter, retrieveAttributes=retrieveAttributes)

def ldap_name(cn):
    logger.debug("Requesting username for: "+cn+"...")

    try:
      return cn.split(',')[0].split('=')[1]
    except:
      return cn

def ldap_names(l):
    logger.debug("Requesting names for list: "+str(l)+"...")

    r = []
    for i in l:
       r.append(ldap_name(i))

    return r

def ldap_get_user(username):
    u = ldap_search('ou=people,'+ldap_domain(), searchScope = ldap.SCOPE_SUBTREE, searchFilter = "uid="+username, retrieveAttributes = ['cn'])
    try:
      return u[0][0][1]['cn'][0] 
    except:
      return None

def ldap_get_description(username):
    u = ldap_search('ou=people,'+ldap_domain(), searchScope = ldap.SCOPE_SUBTREE, searchFilter = "uid="+username, retrieveAttributes = ['description'])
    try:
      return u[0][0][1]['description'] 
    except:
      return []

def ldap_get_password(username):
    u = ldap_search('ou=people,'+ldap_domain(), searchScope = ldap.SCOPE_SUBTREE, searchFilter = "uid="+username, retrieveAttributes = ['userPassword'])
    try:
      return u[0][0][1]['userPassword'][0] 
    except:
      return None

def ldap_user_manages(user):
    g = ldap_search('uid='+user+',ou=people,'+ldap_domain())
    try:
      return ldap_names(g[0][0][1]['manager'])
    except:
      return None

def ldap_group_managers(group):
    m = ldap_search('ou=people,'+ldap_domain(), searchFilter = 'manager=ou='+group+',ou=groups,'+ldap_domain(), retrieveAttributes = ['cn'])
    r = []
    try:
      for i in range(0,len(m)):
        r.append(ldap_name(str(m[i][0][1]['cn'][0])))
    except:
      pass

    return r

def ldap_groups():
    m = ldap_search('ou=groups,'+ldap_domain(), searchFilter = "ou=*", retrieveAttributes = ['ou'])
    r = []
    try:
      for i in range(0,len(m)):
        if m[i][0][0] != 'ou=groups,'+ldap_domain(): 
          r.append(ldap_name(str(m[i][0][1]['ou'][0])))
    except:
      pass

    return r

def ldap_group_members(group):
    m = ldap_search('ou='+group+',ou=groups,'+ldap_domain(), searchFilter = "member=*", retrieveAttributes = ['member'])
    try:
      return ldap_names(m[0][0][1]['member'])
    except:
      return []


def ldap_membership(member):
    m = ldap_search('ou=groups,'+ldap_domain(), searchFilter = "member=uid="+member+",ou=people,"+ldap_domain(), retrieveAttributes = ['ou'])
    r = []
    try:
      for i in range(0,len(m)):
        r.append(ldap_name(str(m[i][0][1]['ou'][0])))
    except:
      pass

    return r

def ldap_check_identified(username):
    descriptions = ldap_get_description(username)
    
    if descriptions:
       for d in descriptions:

          if d.startswith("Identified"):
             return True

    return False

def ldap_update_name(username, firstname, lastname):
    old = ldap_search("ou=people,"+ldap_domain(), searchFilter = "uid="+username, retrieveAttributes = ['givenName', 'sn'])

    dn = "uid="+username+",ou=people,"+ldap_domain()
    ldap_update(dn, { 'givenName':old[0][0][1]['givenName'][0] }, { 'givenName':firstname } )
    ldap_update(dn, { 'sn':old[0][0][1]['sn'][0] }, { 'sn':lastname } )

def ldap_add_description(username, description):
    description_old = ldap_get_description(username)

    description_new = list(description_old)
    description_new.append(description)

    dn = "uid="+username+",ou=people,"+ldap_domain()
    ldap_update(dn, { 'description':description_old }, { 'description':description_new })
