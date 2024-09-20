import requests


def convert_string(convert):
    if not convert:
        return ''
    if isinstance(convert, list):
        return ','.join(convert)
    return convert


class RoleStrategy(object):
    def __init__(self, url, login, password, ssl_verify=True, ssl_cert=None):
        if 'http' not in url:
            raise PyjarsException('Missing http or https', 400, dict(url=url))
        if url[-1:] == '/':
            url = url[-1:]
        self._url = url + '/role-strategy/strategy'
        self._session = self._connect(login, password, ssl_verify, ssl_cert)
        crumb = self._get(
            url +
            '/crumbIssuer/api/xml?xpath=concat(//crumbRequestField,":",//crumb)'
        )
        #if there are no crumb we don't need this below
        if crumb.status_code == 200:
            head = crumb.text.split(':')
            self._session.headers = {str(head[0]): str(head[1])}
        if not self.is_connected():
            raise PyjarsException('Authentification Failed', 401,
                                  dict(
                                      login=login,
                                      password='****',
                                      url=url,
                                      ssl=ssl_verify,
                                      cert=ssl_cert))

    def is_connected(self):
        return self._get(self._url + '/getAllRoles').status_code == 200

    def _connect(self, login, password, ssl_verify, ssl_cert, header=None):
        _s = requests.Session()
        _s.auth = (login, password)
        _s.cert = ssl_cert
        _s.verify = ssl_verify
        _s.headers = header
        return _s

    def _post(self, api_url, data):
        """Return requests.models.Response"""
        return self._session.post(api_url, data=data)

    def _get(self, api_url, data=None):
        """Return requests.models.Response"""
        return self._session.get(api_url, params=data)


class Role:
    def __init__(self, parent, type, roleName):
        self.type = type
        self.roleName = roleName
        self._parent = parent
        self._permissions = []

    def assign_sid(self, sid):
        url = self._parent._url + '/assignRole'
        data = dict(
            type=self.type,
            roleName=self.roleName,
            sid=convert_string(sid), )
        return self._parent._post(url, data=data)

        
class GetRole:
    def __init__(self, parent, type):
        self.type = type
        self._parent = parent

    def list_roles(self):
        url = self._parent._url + '/getAllRoles'
        query = self._parent._get(url)
        if query.status_code != 200:
            query.raise_for_status()
        try:
            return query.json()
        except KeyError:
            return []


class PyjarsException(Exception):
    def __init__(self, message, code, data):
        self.error = dict(
            message=message,
            status_code=code,
            data=data, )