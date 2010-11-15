"""
(C) 2010 - Marcin Wielgoszewski (Gotham Digital Science)

CSAW 2010 Cryptography Challenges
"""
from utils import *
import cherrypy
import hashlib
import os
import time
import urlparse
import uuid


LOGIN = """<html>
  <head>
    <title>CSAW 2010 Crypto CTF Final</title>
  </head>
  <body>
    <h1>Welcome to the CSAW 2010 CTF Finals Crypto Challenge</h1>
    <p>Please login to continue:</p>
    <form action="login" method="POST" autocomplete="off">
        <table>
            <tr>
                <td>Name:</td>
                <td><input type="text" name="user" /></td>
            </tr>
            <tr>
                <td>Password:</td>
                <td><input type="text" name="password" type="password" /></td>
            </tr>
            <tr>
                <td></td>
                <td><input type="submit" /></td>
            </tr>
        </table>
    </form>
  </body>
</html>
"""

SUCCESS = """<html>
  <head>
    <title>CSAW 2010 Crypto CTF Final</title>
  </head>
  <body>
    <p>Congratulations on completing this challenge! Here is your flag: %s</p>
  </body>
</html>
"""

ERROR = """<html>
  <head>
    <title>Internal Server Error</title>
  </head>
  <body>
    <h1>Internal Server Error</h1>
    <p>%s</p>

    <!--
        Error:   %s
        Date:    %s
        IP Addr: %s

        This page served in %.9f seconds.
    -->
  </body>
</html>
"""


KEY = hashlib.md5('GDS_CSAW_FINAL').digest()


class CSAW:
    @cherrypy.expose
    def index(self):
        raise cherrypy.HTTPRedirect("/login", 302)


    @cherrypy.expose
    def login(self, user=None, password=None):
        start = time.time()

        if user is None or password is None:
            cherrypy.log("No username/password")

            if 'csaw' in cherrypy.request.cookie:
                cherrypy.log("Redircting to protected")
                raise cherrypy.HTTPRedirect("/protected", 302)
            else:
                return LOGIN

        if len(user) < 5:
            return ERROR % ('Username must be at least 6 characters',
                            str(uuid.uuid4()),
                            time.ctime(),
                            cherrypy.request.remote.ip,
                            (time.time() - start))

        if user.lower() == 'admin':
            return ERROR % ('Sorry, admin user cannot login from this IP',
                            str(uuid.uuid4()),
                            time.ctime(),
                            cherrypy.request.remote.ip,
                            (time.time() - start))

        cookievalue = "user=%s&role=%s" % (user, 'guest')
        cookievalue += "&t=%s" % e_b64(sign(cookievalue, KEY), url=True)

        cherrypy.response.cookie['csaw'] = e_b64(cookievalue, url=True)
        cherrypy.response.cookie['csaw'].secure = True

        raise cherrypy.HTTPRedirect("/protected", 302)


    @cherrypy.expose
    def protected(self):
        start = time.time()

        if not 'csaw' in cherrypy.request.cookie:
            return LOGIN

        cookie = cherrypy.request.cookie.get('csaw').value
        request = dict(urlparse.parse_qsl(d_b64(cookie, url=True)))
        signature = sign("user=%s&role=%s" % (request.get('user', ''), request.get('role', '')), KEY)

        try:
            result, elapsed = is_equal2(signature, d_b64(request.get('t', ''), url=True))
        except TypeError:
            result, elapsed = False, (time.time() - start)

        if result is False:
            cherrypy.log("result is %r, elapsed = %.9f" % (result, elapsed))
            return ERROR % ('Sorry, an error has occurred.',
                            str(uuid.uuid4()),
                            time.ctime(),
                            cherrypy.request.remote.ip,
                            elapsed)

        if request.get('role') == 'admin' or request.get('user') == 'admin':
            cherrypy.log("user: %r ; role: %r" % (request.get('role'), request.get('user')))
            return SUCCESS % CSAW_CRYPTO_FINAL_FLAG.encode('hex')

        raise cherrypy.HTTPError(403, 'Only users in the "admin" group are allowed access to this resource')


cherrypy.tree.mount(CSAW())


if __name__ == "__main__":
    import os.path
    from getpass import getpass

    CSAW_CRYPTO_FINAL_FLAG = sign(getpass('Please enter the final flag key: '), KEY)

    thisdir = os.path.dirname(__file__)
    cherrypy.quickstart(config=os.path.join(thisdir, 'csaw.crypto.conf'))
