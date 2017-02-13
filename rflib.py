#!/usr/bin/env python
"""
rflib - A basic library for managing Redfish compatible servers.

Example use:

  from rflib import RFConnection
  conn = RFConnection("host", "user", "pass")
  conn.auth()
  root = conn.get_root()
  print root.systems[0].model
  conn.deauth()

"""

import os
from urlparse import urljoin
import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


class RFOpts(object):
  """
  A utility class for parsing common command line parameters.
  """

  @staticmethod
  def expand_hosts(hostexp):
    """
    This function converts a pdsh-style host specification into a list of hosts.
    The following are example input/outputs:
      'abc000'        -> ['abc000']
      'abc01[5-6]'    -> ['abc015','abc016']
      'abc0[01-03]'   -> ['abc001','abc002','abc003']
      'abc00[1,4]'    -> ['abc001','abc004']
      'abc0[17]'      -> ['abc017']
      'abc[001-002]t' -> ['abc001t','abc002t']
    """
    if not "[" in hostexp or not "]" in hostexp:
      return [hostexp]
    hosts = []
    head, rest = hostexp.split("[", 1)
    exp, tail = rest.split("]", 1)
    for exp_val in exp.split(","):
      if "-" in exp_val:
        exp_start, exp_end = exp_val.split("-", 1)
        exp_len = len(exp_start)
        for i in xrange(int(exp_start, 10), int(exp_end, 10)+1):
          hosts.append("%s%s%s" % (head, str(i).zfill(exp_len), tail))
      else:
        hosts.append("%s%s%s" % (head, exp_val, tail))
    return hosts


class RFValueIter(object):
  """
  An iterator object used for Redfish collections.
  It works like a normal list iterator but calls resolve() on each value
  before returning it.
  """

  def __init__(self, list_val):
    """ Prepare to iterate over the given list (list_val). """
    self._list = list_val
    self._iter = iter(self._list)

  def __iter__(self):
    """ Reset the iterator. """
    self._iter = iter(self._list)
    return self

  def next(self):
    """ Get the next value, resolve and return it. """
    return self._iter.next().resolve()

  def get_list(self):
    """ Returns a reference to the list. """
    return self._list


class RFValue(object):
  """
  This class represents a mapping of a Redfish value to a Python object.
  The object can be of type:
    TYPE_UNKNOWN - Anything not covered by the other types (dictionaries).
    TYPE_STR - A standard string.
    TYPE_OBJ - Another object (RFObject).
    TYPE_LIST - A list of items (generally a collection of objects).
  """

  TYPE_UNKNOWN = 0
  TYPE_STR = 1
  TYPE_OBJ = 2
  TYPE_LIST = 3

  def __init__(self, obj_name, obj_val, conn):
    """ Creates a value representation.
        obj_name is the name of the value within an object.
        obj_val is the value to store (type is automatically detected).
        conn is the parent RFConnection object (used to fetch other objects
             if they are referenced).
    """
    self._name = obj_name
    self._conn = conn
    self._type = self.TYPE_UNKNOWN
    self._val = obj_val
    if isinstance(obj_val, unicode):
      self._val = obj_val.encode('ascii')
      self._type = self.TYPE_STR
    elif isinstance(obj_val, dict):
      if '@odata.id' in obj_val:
        self._val = obj_val['@odata.id'].encode('ascii')
        self._type = self.TYPE_OBJ
    elif isinstance(obj_val, list):
      self._val = []
      self._type = self.TYPE_LIST
      for list_item in obj_val:
        self._val.append(RFValue(None, list_item, self._conn))

  def name(self):
    """ Returns the value name.
        Note that this may be None for anonymous values (such as items in a
        collection).
    """
    return self._name

  def resolve(self):
    """ Resolves this value.
        For most value types, this simply returns the value.
        For objects (which are generally referenced by another object), this
        fetches the referenced object from the server and returns that,
        allowing simple recursion of the server namespace.
    """
    if self._type == self.TYPE_OBJ:
      return self._conn.get_obj(self._val)
    elif self._type == self.TYPE_LIST:
      return self
    else:
      return self._val

  def __iter__(self):
    """ Returns an iterator if this is a list-type value, otherwice None. """
    if self._type == self.TYPE_LIST:
      return RFValueIter(self._val)
    else:
      return None

  def __getitem__(self, item_num):
    """ Gets a specific item for a list-type value, otherwise throws a
        TypeError.
    """
    if self._type == self.TYPE_LIST:
      return self._val[item_num].resolve()
    else:
      raise TypeError("RFValue is not a list.")

  def __repr__(self):
    """ Returns a representation of this value. """
    return "<rflib.RFValue object %s:%s ('%s')>" % (self._name,
                                                    self._type, self._val)

  def __str__(self):
    """ For string type values returns the raw string, otherwise returns the
        representation value.
    """
    if self._type == self.TYPE_STR:
      return self._val
    else:
      return self.__repr__()


class RFObject(object):
  """ A python object that represents a Redfish object. """

  def __init__(self, conn, obj_path, json_obj):
    """ Create a new representation of an object.
        conn - The connection used to fetch this object (used for reloading).
        obj_path - The full path on the server to this object.
        json_obj - The raw data for this object (or None to fetch it from the
                   server with conn.
    """
    self._conn = conn
    self._path = obj_path
    self.reload(json_obj)

  def reload(self, json_obj=None):
    """ Refreshes the representation of this object.
        All values contained within this object are purged and the object
        is refilled. If a JSON decoded object 'json_obj' is provided then
        that is used as the source data, otherwise the object JSON is
        re-downloaded from the server.
    """
    if not json_obj:
      _, json_obj, _ = self._conn.http_req(self._path)
    self._items = {}
    self._json = json_obj
    for iname, ival in self._json.iteritems():
      attr_name = iname.encode('ascii').lower()
      attr_item = RFValue(attr_name, ival, self._conn)
      self._items[attr_name] = attr_item

  def action(self, action_name, params):
    """ Call a given action on the server.
        params should be a dictionary of the expected parameters.
    """
    actions = self._items['actions'].resolve()
    if not action_name in actions:
      raise NameError("Unknwon action '%s'" % action_name)
    target = actions[action_name]['target']
    self._conn.http_req(target, method='POST', data=params)

  def __iter__(self):
    if 'members' in self._items:
      return iter(self._items['members'])
    else:
      return iter(self._items)

  def __getattr__(self, attr_name):
    attr_name = attr_name.lower()
    if attr_name in self._items:
      return self._items[attr_name].resolve()
    else:
      raise AttributeError

  def __setattr__(self, attr_name, attr_value):
    if attr_name.startswith('_'):
      return super(RFObject, self).__setattr__(attr_name, attr_value)
    self._conn.http_req(self._path, method='PATCH',
                        data={attr_name: attr_value})
    self.reload() # Object may have changed

  def __repr__(self):
    return "<rflib.RFObject object %s (%s)>" % (self._path, self._json)

  def get_item(self, item_name):
    """ Get an item from this object.
        Generally this will return a resolved value of the given name.
        If this item is a collection, an integer index may also be provided.
    """
    if isinstance(item_name, str):
      item_name = item_name.lower()
    if 'members' in self._items and isinstance(item_name, int):
      return self._items['members'][item_name]
    else:
      return self._items[item_name].resolve()

  def __getitem__(self, item_name):
    if isinstance(item_name, str):
      item_name = item_name.lower()
    return self.get_item(item_name)



class RFConnection(object):
  """ A connection to a specific Redfish server.
  """

  def __init__(self, host, auth_user=None, auth_pass=None, insecure=True):
    self._host = host
    self._baseurl = "https://%s" % host
    self._token = None
    self._session_obj = None
    self._verify = not insecure
    self._root_path = '/redfish/v1'
    if not auth_user:
      if "IPMIUSER" in os.environ:
        auth_user = os.environ["IPMIUSER"]
      else:
        raise AttributeError("auth_user parameter missing")
    if not auth_pass:
      if "IPMIPASS" in os.environ:
        auth_pass = os.environ["IPMIPASS"]
      else:
        raise AttributeError("auth_pass parameter missing")
    self._auth = (auth_user, auth_pass)

  def __del__(self):
    """ Deauthenticates from the server if required to prevent idle
        sessions being left open if at all possible.
    """
    self.deauth()

  def http_req(self, obj_path, method='GET',
               data=None, with_auth=True):
    """ Send a HTTP request to the server.
        obj_path - The full path to use.
        method - Uppercase HTTP verb string (GET/POST/PATCH/DELETE).
        data - An object to be JSON encoded and sent as POST data.
        with_auth - Send authentication information (either username/pass
                    or token).
        Returns a decoded JSON object or None if the server didn't
        return any content.
    """
    full_url = urljoin(self._baseurl, obj_path)
    headers = {'Content-Type': 'application/json;charset=utf-8',
               'Accept': 'application/json;charset=utf-8',
               'OData-Version': '4.0'}
    auth = None
    if with_auth:
      if self._token:
        headers['X-Auth-Token'] = self._token
      else:
        auth = self._auth
    req_func = requests.get
    if method == 'POST':
      req_func = requests.post
    elif method == 'DELETE':
      req_func = requests.delete
    elif method == 'PATCH':
      req_func = requests.patch
    # Actually run the request
    res = req_func(full_url, auth=auth, json=data,
                   headers=headers, verify=self._verify)
    obj_name = obj_path
    if 'Location' in res.headers:
      obj_name = res.headers['Location']
    auth_token = None
    if 'X-Auth-Token' in res.headers:
      auth_token = res.headers['X-Auth-Token']
    if len(res.text):
      obj_data = res.json()
      return (obj_name, obj_data, auth_token)
    else:
      return None

  def get_obj(self, obj_path):
    """ Returns an object from the server by path. """
    obj_path, obj_data, _ = self.http_req(obj_path)
    return RFObject(self, obj_path, obj_data)

  def get_root(self):
    """ Returns the root object from the server. """
    return self.get_obj(self._root_path)

  def auth(self):
    """ Authenticate against the Redfish server.
        This function uses the username & password provided in the
        constructor to create a new session on the server and
        request a token. The token will then be use for all future
        requests until deauth() is called.
    """
    auth_data = {'UserName': self._auth[0],
                 'Password': self._auth[1]}
    obj_name, _, auth_token = self.http_req("/redfish/v1/Sessions",
                                            method='POST',
                                            data=auth_data,
                                            with_auth=False)
    self._session_obj = obj_name
    self._token = auth_token

  def deauth(self):
    """ Deauthenticate from the Redfish server.
        If a session exists, it is deleted from the Redfish server.
        After calling this, all requests will go back to using plain
        username/password authentication.
    """
    if not self._token:
      return
    self.http_req(self._session_obj, method='DELETE')
    self._session_obj = None
    self._token = None
