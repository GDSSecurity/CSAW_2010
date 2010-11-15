"""
(C) 2010 - Marcin Wielgoszewski (Gotham Digital Science)

CSAW 2010 Cryptography Challenges
"""
from utils import *
import cherrypy
import hashlib
import struct
import time

AUTHENTICATE = False

CSAW_SIGNING_KEY   = hashlib.md5('B7CMa2uRld5AwocV+3JXzw=='.decode('base64')).hexdigest()

CSAW_CRYPTO_1_KEY  = hashlib.md5('GDS_CSAW_1').hexdigest()
CSAW_CRYPTO_2_KEY  = hashlib.md5('GDS_CSAW_2').hexdigest()
CSAW_CRYPTO_3_KEY  = hashlib.md5('GDS_CSAW_3').hexdigest()
CSAW_CRYPTO_4_KEY  = hashlib.md5('GDS_CSAW_4').digest()

CSAW_CRYPTO_2_CHALLENGE_TOKEN = 'She sells CSAW by the seashore'
CSAW_CRYPTO_3_CHALLENGE_TOKEN = 'Oh yah, just add a random sleep'
CSAW_CRYPTO_4_CHALLENGE_TOKEN = 'Two blocks, one swap'

# sign('Duong, Rizzo, and Vaudenay', CSAW_SIGNING_KEY)
CSAW_CRYPTO_1_FLAG = '43fb994b59e8bb99d99ef969d773ea98'

# sign("If You're Typing The Letters A-E-S Into Your Code, You're Doing It Wrong", CSAW_SIGNING_KEY)
CSAW_CRYPTO_2_FLAG = '8ee38021f40ef94e6725e9be07b49951'

# REMOVED
#CSAW_CRYPTO_3_FLAG = <REMOVED>

# sign("Chris Eng: Crypto for Pentesters", CSAW_SIGNING_KEY)
CSAW_CRYPTO_4_FLAG = 'f6079ee33a491ef1b5fae2cf747dd0db'


INDEX = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <h1>Welcome to the CSAW 2010 Crypto Challenges!</h1>

    <p>There are three individual crypto challenges to complete, each of
       varying difficulty.  Have your crack at the first challenge below,
       or try one of the other challenges:
       <ul>
        <li><a href="/challenge2" title="CSAW 2010 Crypto Challenge #2">CSAW 2010 Crypto Challenge #2</a></li>
        <li><a href="/challenge3" title="CSAW 2010 Crypto Challenge #3">CSAW 2010 Crypto Challenge #3</a></li>
        <li><a href="/bonus" title="CSAW 2010 Crypto Bonus Challenge">CSAW 2010 Crypto Bonus Challenge</a></li>
       </ul>
    </p>

    <form action="challenge1" method="POST">
        <table>
            <tr>
                <td>Name:</td>
                <td><input type="text" name="name" /></td>
            </tr>
            <tr>
                <td>Team Name:</td>
                <td><input type="text" name="team" /></td>
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

WELCOME_CHALLENGE_1 = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <p>Welcome to CSAW 2010 Crypto Challenge #1, %s!  You are not an admin yet, try again!</p>
</body>
</html>
"""

WELCOME_CHALLENGE_2 = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <p>Welcome to CSAW 2010 Crypto Challenge #1, guest!  You are not an admin yet, try again!</p>
    <p>You're role is currently level 5, however this area requires
       a role level of 0.  Please see system administrator if you feel
       this is in error.
    </p>
</body>
</html>
"""

WELCOME_CHALLENGE_4 = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <p>Welcome to CSAW 2010 Crypto Challenge #4 (bonus round).
       This application allows authorized users to perform <i>rlogin</i> over the web,
       however accounts are not just granted to anyone.  In addition, the
       following configuration hardening has been applied:<br /><br />
       <tt>PermitRootLogin no</tt></p>
    </p>

    <form action="bonus" method="post">
        <table>
            <tr>
                <td>Username:</td>
                <td><input type="text" name="rlogin" /></td>
                <td><input type="submit" /></td>
            </tr>
        </table>
        <input type="hidden" name="t" value="0" />
    </form>
</body>
</html>
"""

RETURNING_CHALLENGE_1 = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <p>Welcome back to CSAW Crypto Challenge #1, %s (of team %s)!
       You are just a user (still), keep trying.  You're role is level
       5, but you need a role level of 0 to continue.
    </p>
    <p><i>
        Two roads diverged in a yellow wood,<br />
        And sorry I could not travel both<br />
        And be one traveler, long I stood<br />
        And looked down one as far as I could<br />
        To where it bent in the undergrowth.<br /><br />

        Then took the other, as just as fair,<br />
        And having perhaps the better claim,<br />
        Because it was grassy and wanted wear;<br />
        Though as for that the passing there<br />
        Had worn them really about the same.<br /><br />

        And both that morning equally lay<br />
        In leaves no step had trodden black.<br />
        Oh, I kept the first for another day!<br />
        Yet knowing how way leads on to way,<br />
        I doubted if I should ever come back.<br /><br />

        I shall be telling this with a sigh<br />
        Somewhere ages and ages hence:<br />
        Two roads diverged in a wood, and I--<br />
        I took the one less traveled by,<br />
        And that has made all the difference.<br /><br />
       </i>
       --<strong>Robert Frost</strong>
    </i></p>
</body>
</html>
"""

RETURNING_CHALLENGE_2 = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <p>Welcome back to CSAW 2010 Crypto Challenge #2, %s (of team %s).
       You're role is currently level %s, however this area requires
       a role level of 0.  Please see system administrator if you feel
       this is in error.
    </p>
    <p><i>
    It's funny how we see things upside down...<br />
    And up until now,<br />
    I had no idea.<br />
    Foolishly thinking that was how things were supposed to be.<br />
    Nothing's changed;<br />
    But everything's different.<br />
    The knowledge is enough,<br />
    To move mountains, shift opinions<br />
    I'm seeing the same old view,<br />
    But now it's upside down.<br /><br />
    -marinashutup (http://quizilla.teennick.com/user/marinashutup/profile/)
    </i></p>
</body>
</html>
"""

RETURNING_CHALLENGE_4 = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <p>Welcome back to CSAW 2010 Crypto Challenge #4, <i>%s</i>.</p>
    <p>Unfortunately your user has not yet been provisioned access to
       this system.  Please email the system administrator if you feel 
       this is an error, otherwise please try again.  (remember, usernames
       are case-sensitive!)
    </p>
    <form action="bonus" method="post">
        <table>
            <tr>
                <td>Username:</td>
                <td><input type="text" name="rlogin" /></td>
                <td><input type="submit" /></td>
            </tr>
        </table>
        <input type="hidden" name="t" value="0" />
    </form>
    <!--  request time: %d
         miscellaneous: %s
    -->
</body>
</html>
"""

SUCCESS_CHALLENGE_1 = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <p>Congratuations %s (of team %s)!  You have successfully completed
       CSAW 2010 Crypto Challenge #1.</p>
    <p>Here's your flag: %s</p>

    <p>Now try the next challenge:</p>

    <form action="challenge2" method="post">
        <table>
            <tr>
                <td><input type="text" name="role" value="%s" /></td>
                <td><input type="submit" /></td>
            </tr>
        </table>
    </form>
</body>
</html>
"""

SUCCESS_CHALLENGE_2 = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <p>Congratuations %s (of team %s)!  You have successfully completed
       CSAW 2010 Crypto Challenge #2.</p>
    <p>Here's your flag: %s</p>

    <p>For the next challenge, you need to specify to impersonate the
       <i>Administrator</i> user. Good luck!
    </p>

    <form action="challenge3" method="get">
        <table>
            <tr>
                <td>Username:</td>
                <td><input type="text" name="user" value="%s" /></td>
            </tr>
            <tr>
                <td>Key:</td>
                <td><input type="text" name="key" value="%s" /></td>
            </tr>
            <tr>
                <td><input type="submit" /></td>
                <td></td>
            </tr>
        </table>
    </form>
</body>
</html>
"""

SUCCESS_CHALLENGE_4 = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <p>Congratuations!  You have successfully completed then Bonus challenge!
       This concludes the Cryptography challenges at CSAW 2010.
    </p>
    <p>Here's your flag: %s</p>
</body>
</html>
"""

ERROR_PAGE = """<html><title>CSAW 2010 Crypto Challenges</title>
<body>
    <h1>An error has occurred.</h1>
    <p>Reason: %s</p>
</body>
</html>
"""


class CSAW:
    @cherrypy.expose
    def index(self):
        '''The index page'''
        return INDEX

    @cherrypy.expose
    def challenge(self):
        return INDEX

    @cherrypy.expose
    def challenge1(self, name=None, team=None):
        '''CBC padding oracle attack'''
        sid = cherrypy.request.cookie.get('SID', None)

        if not name or not team:
            if not sid:
                return self.index()

        if sid and not name:
            try:
                ptext = aes_decrypt(sid.value, CSAW_CRYPTO_1_KEY, codec='base64')
            except TypeError:
                cherrypy.log("Caught exception during AES decryption... returning index", context="CRYPTO")
                return self.index()

            # this is where we introduce a CBC padding oracle vulnerability
            padding_length = struct.unpack("B", ptext[-1])[0]
            good = (ptext[-padding_length:] == struct.pack("B", padding_length) * padding_length)

            if good is False:
                # TOO EASY
                #raise BadPaddingError
                # return a very subtle difference in the error page...
                cherrypy.log("Caught BadPaddingError", context="CRYPTO")
                return ERROR_PAGE % "Sorry, an error had occurred."
            else:
                ptext = ptext[:-padding_length]

            try:
                role = ptext.split('|')[3][-1]
            except IndexError:
                cherrypy.log("Caught exception trying to get role\n", context="CRYPTO", traceback=True)
                role = None

            try:
                username, teamname = ptext.split('|')[1:3]
            except ValueError:
                cherrypy.log("Caught exception trying to get username, teamname\n", context="CRYPTO", traceback=True)
                return ERROR_PAGE % "Sorry, an error has occurred."

            if role == '0':
                if AUTHENTICATE is True:
                    cookie = cherrypy.response.cookie
                    token = aes_encrypt_then_sign(CSAW_CRYPTO_2_CHALLENGE_TOKEN, CSAW_CRYPTO_2_KEY, CSAW_SIGNING_KEY)
                    cookie['c2'] = token

                nextchallenge = aes_encrypt("CSAW 2010 CRYPTO #02|%s|%s|BLAHCHALLENGEAAAAA|role=5" % (username, teamname), CSAW_CRYPTO_2_KEY)

                return SUCCESS_CHALLENGE_1 % (e_html(username), e_html(teamname), CSAW_CRYPTO_1_FLAG, nextchallenge)

            else:
                return RETURNING_CHALLENGE_1 % (e_html(username), e_html(teamname))

        else:
            cookie = cherrypy.response.cookie
            challenge = 'CSAW 2010 CRYPTO #01|%s|%s|role=5|CHALLENGE' % (name, team)
            cookie['SID'] = aes_encrypt(challenge, CSAW_CRYPTO_1_KEY, codec='base64')
            return WELCOME_CHALLENGE_1 % e_html(name)


    @cherrypy.expose
    def challenge2(self, role=None):
        '''Bit flipping attack'''
        if AUTHENTICATE is True:
            c2 = cherrypy.request.cookie.get('c2')
            if not authorize(c2, CSAW_CRYPTO_2_KEY, CSAW_SIGNING_KEY, CSAW_CRYPTO_2_CHALLENGE_TOKEN):
                return self.index()

        if role is None:
            c2 = cherrypy.request.cookie.get('c2')
            if c2:
                role = c2.value
            else:
                token = aes_encrypt("CSAW 2010 CRYPTO #02|%s|%s|BLAHCHALLENGEAAAAA|role=5" % ('guest', 'guest'), CSAW_CRYPTO_2_KEY)
                cherrypy.response.cookie['c2'] = token
                return WELCOME_CHALLENGE_2

        # OK, we got this far..  they've passed the correct challenge token
        # this is a bit flipping challenge, so flip 1 bit to get role=0
        token = aes_decrypt(role, CSAW_CRYPTO_2_KEY)
        username, teamname, = token.split('|')[1:3]

        padding_length = struct.unpack("B", token[-1])[0]
        roleid = token[:-padding_length].rsplit('|', 1)[-1]


        if roleid[-1] == '0':
            if AUTHENTICATE is True:
                token = aes_encrypt_then_sign(CSAW_CRYPTO_3_CHALLENGE_TOKEN, CSAW_CRYPTO_3_KEY, CSAW_SIGNING_KEY)
                cherrypy.response.cookie['c3'] = token
            signature = e_b64(sign('guest', CSAW_SIGNING_KEY), '-', '_').rstrip('=').rstrip()

            return SUCCESS_CHALLENGE_2 % (e_html(username), e_html(teamname), CSAW_CRYPTO_2_FLAG, "guest", signature)
        else:
            return RETURNING_CHALLENGE_2 % (e_html(username), e_html(teamname), e_html(roleid[-1]))


    @cherrypy.expose
    def challenge3(self, user=None, key=None):
        '''Removed'''
        return "Challenged Removed"


    @cherrypy.expose
    def bonus(self, rlogin="", t=""):
        if t == '0':
            if '|' in rlogin:
                return ERROR_PAGE % "Sorry, you cannot use pipes in your name."

        if 'admin' == rlogin.lower() or 'root' == rlogin.lower():
            return ERROR_PAGE % "Sorry, root/admin cannot login remotely."

        if 'CSAW_ID' in cherrypy.request.cookie and not rlogin:
            rlogin = cherrypy.request.cookie.get('CSAW_ID').value

        if (t == '1' and rlogin) or (rlogin and not t):
            try:
                ptext = des_decrypt(rlogin, CSAW_CRYPTO_4_KEY)
            except TypeError, e:
                return ERROR_PAGE % "INVALID TOKEN"
            except IllegalBlockSizeError, e:
                return ERROR_PAGE % e

            try:
                timestamp, userid, m = ptext.split('|')
                padding_length = struct.unpack("B", m[-1])[0]
                m = m[:-padding_length].rsplit('|', 1)[-1]
            except ValueError:
                return ERROR_PAGE % "INVALID TOKEN"

            # validate timestamp is within 5 minutes:
            try:
                if (time.time() * 1000) - int(timestamp) > 300000:
                    cookie = cherrypy.response.cookie
                    cookie['CSAW_ID'] = ''
                    cookie['CSAW_ID']['expires'] = 0
                    return ERROR_PAGE % "TIMESTAMP EXPIRED"

            except ValueError:
                return ERROR_PAGE % "INVALID TIMESTAMP"

            if userid in ['root', 'admin']:
                return SUCCESS_CHALLENGE_4 % CSAW_CRYPTO_4_FLAG
            else:
                return RETURNING_CHALLENGE_4 % (e_html(userid), int(timestamp), e_html(m))

        elif t == '0':
            token = "%15d|%s|CSAW_CHALLENGE#4" % (time.time() * 1000, rlogin)
            ctext = des_encrypt(token, CSAW_CRYPTO_4_KEY)
            cherrypy.response.cookie['CSAW_ID'] = ctext

            raise cherrypy.HTTPRedirect("/bonus?t=1&rlogin=%s" % ctext, 302)
        else:
            return WELCOME_CHALLENGE_4


cherrypy.tree.mount(CSAW())


if __name__ == '__main__':
    import os.path
    thisdir = os.path.dirname(__file__)
    cherrypy.quickstart(config=os.path.join(thisdir, 'csaw.crypto.conf'))

