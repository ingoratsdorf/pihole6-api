import requests
import datetime as dt
from dateutil.relativedelta import relativedelta
import dateutil.parser as date_parser
from enum import Enum

# The PiHole 6 developmment version of the API documentation can be found here:
# https://ftl.pi-hole.net/development-v6/docs/#

class QueryActionType(Enum):
    GRAVITY = 1
    FORWARDED = 2
    CACHE = 3
    BLOCKED_WILDCARD = 4
    UNKNOWN = 5


class AuthRequired(Exception):
    pass


class QueryException(Exception):
    pass

class GeneralException(Exception):
    pass

def requires_auth(api_func):
    """Decorator to check auth_data is present for given api method."""

    def wrapper(self, *args, **kwargs):
        if not self.password:
            raise AuthRequired('Authentication is required!')
        return api_func(self, *args, **kwargs)

    return wrapper

class PiHole6(object):

    # Helper functions

    known_time_ranges = {
        "today": (dt.datetime.combine(dt.datetime.now(dt.timezone.utc).date(), dt.datetime.min.time()), dt.datetime.now(dt.timezone.utc)),
        "yesterday": (dt.datetime.combine(dt.datetime.now(dt.timezone.utc).date()-dt.timedelta(days=1), dt.datetime.min.time()),
                      dt.datetime.combine(dt.datetime.now(dt.timezone.utc).date()-dt.timedelta(days=1), dt.datetime.max.time())),
        "last_7_days": (dt.datetime.combine(dt.datetime.now(dt.timezone.utc).date()-dt.timedelta(days=6), dt.datetime.min.time()),
                        dt.datetime.now(dt.timezone.utc)),
        "last_30_days": (dt.datetime.combine(dt.datetime.now(dt.timezone.utc).date()-dt.timedelta(days=29), dt.datetime.min.time()),
                         dt.datetime.now(dt.timezone.utc)),
        "this_month": (dt.datetime.combine(dt.date(dt.datetime.now(dt.timezone.utc).date().year,dt.datetime.now(dt.timezone.utc).date().month,1),
                                           dt.datetime.min.time()),
                       dt.datetime.now(dt.timezone.utc)),
        "last_month": [dt.datetime.combine(dt.date(dt.datetime.now(dt.timezone.utc).date().year,dt.datetime.now(dt.timezone.utc).date().month,1)-relativedelta(months=1),
                                           dt.datetime.min.time()),
                       dt.datetime.combine(dt.date(dt.datetime.now(dt.timezone.utc).date().year,dt.datetime.now(dt.timezone.utc).date().month,1)-dt.timedelta(days=1),
                                           dt.datetime.max.time())],
        "this_year": (dt.datetime.combine(dt.date(dt.datetime.now(dt.timezone.utc).date().year,1,1), dt.datetime.min.time()),
                      dt.datetime.now(dt.timezone.utc)),
        "all_time": (0, dt.datetime.now(dt.timezone.utc))
    }

    def __init__(self, ip_address, scheme:str = "http", port:int = 80, password: str = ''):
        """
        Purpose: Initialises the class
        Takes in an ip address of a pihole server; using http over port 80 by default
        """
        self.scheme = scheme
        self.ip_address = ip_address
        self.port = port
        self.session = None
        self.api_url = self.scheme + "://" + self.ip_address + ":" + str(self.port) + "/api/"
        self.password = password
        #self.refresh()
    # end def

    def _auth(self):
        """
        Purpose: Uses supplied password to (re)authenticate on the server
        """
        try:
            # Cannot use the below API call for this as this would create a rircular loop if not authenticated
            response = requests.post(self.api_url + 'auth', json={"password":self.password})
        except:
            raise GeneralException('Unknown error occurred!')
        data=response.json()
        data['status_code'] = response.status_code
        if response.status_code == 200:
            # We have a valid result and store the session
            self.session = data['session']
        else:
            # other response codesa as per API:
            # 400, 401, 429
            self.session = None
        return(data)
    # end def

    def api_call(self, method: str, endpoint: str, json: object = None, attempt: int = 0):
        """
        Purpose: Queries server with a GET call

        :param method: request method to call, allowed methods: GET, POST, PATCH, PUT, DELETE
        :param endpoint: path part after the /api part 
        :param params: parameters in json format that the API call expects
        """

        if not self.session:
            if not self.password:
                # Cannot authenticate without password, obviously
                # Maybe some servers don't have one. Should we fail here or not?
                raise AuthRequired('Authentication is required but no password has been supplied!')
            # Authenticate with given password
            self._auth()
        try:
            response = requests.request(method, self.api_url + endpoint, json=json, headers={"sid":self.session["sid"]})
        except:
            raise GeneralException('Unknown error occurred!')
        data = response.json()
        data['status_code'] = response.status_code
        if (response.status_code == 401) and (attempt != 0):
            # not authenticated
            if (endpoint == 'auth'):
                # we had and auth failure trying to log out. well, let's just ignore this
                pass
            else:
                # Although we had a valid session, the session may have expired and thus we need to redo the call
                # 2nd call with auth again at the start
                # if the password is not set, it will raise an exception, otherwise auth and create a new session
                self.session = None
                data = self.api_call(self, method, endpoint, json, attempt=1)
        return(data)
    # end def

    # DNS control
    # Methods used to control the behavior of your Pi-hole

    def blockingGet(self):
        """
        Purpose: Get current blocking status
        The property timer may contain additional details concerning a temporary en-/disabling. It is null when no timer is active (the current status is permanent).

        """
        return (self.api_call(method='GET', endpoint='dns/blocking'))
    # end def

    def blockingSet(self, enabled: bool, timer: int):
        """
        Purpose: Change current blocking status
        Change the current blocking mode by setting blocking to the desired value. The optional timer object may used to set a timer. Once this timer elapsed,
        the opposite blocking mode is automatically set. For instance, you can request {blocking: false, timer: 60} to disable Pi-hole for one minute.
        Blocking will be automatically resumed afterwards.

        :param enabled: Blocking status
        :param timer: Remaining seconds until blocking mode is automatically changed
        """
        return (self.api_call(method='POST', endpoint='dns/blocking', json={"blocking": enabled, "timer": timer}))
    # end def
    
    # Authentication
    # Methods used to get usage data from your Pi-hole

    def authCheck(self):
        """
        Purpose: Check if authentication is required
        The API may chose to reply with a valid session if no authentication is needed for this server.
        """
        return (self.api_call(method='GET', endpoint='auth'))
    # end def

    def authSetPassword(self, password: str):
        """
        Purpose: Submit password for login
        Authenticate using a password. The password isn't stored in the session nor used to create the session token.
        Instead, the session token is produced using a cryptographically secure random number generator.
        A CSRF token is utilized to guard against CSRF attacks and is necessary when using Cookie-based authentication.
        However, it's not needed with other authentication methods.
        Both the Session ID (SID) and CSRF token remain valid for the session's duration.
        The session can be extended before its expiration by performing any authenticated action.
        By default, the session lasts for 5 minutes. It can be invalidated by either logging out or deleting the session.
        Additionally, the session becomes invalid when the password is altered or a new application password is created.
        If two-factor authentication (2FA) is activated, the Time-based One-Time Password (TOTP) token must be included in the request body.
        Be aware that the TOTP token, generated by your authenticator app, is only valid for 30 seconds.
        If the TOTP token is missing, invalid, or has been used previously, the login attempt will be unsuccessful.
        """
        self.password = password
        self.auth()
        return(self.session)
    # end def

    def authLogout(self):
        """
        Purpose: Delete session
        This endpoint can be used to delete the current session. It will invalidate the session token and the CSRF token.
        The session can be extended before its expiration by performing any authenticated action. By default, the session lasts for 5 minutes.
        It can be invalidated by either logging out or deleting the session. Additionally,
        the session becomes invalid when the password is altered or a new application password is created.
        You can also delete a session by its ID using the DELETE /auth/session/{id} endpoint.
        Note that you cannot delete the current session if you have not authenticated (e.g., no password has been set on your Pi-hole).
        """
        return (self.api_call(method='DELETE', endpoint='auth'))
    # end def

    def authCreateApp(self):
        """
        Purpose: Create new application password
        Create a new application password. The generated password is shown only once and cannot be retrieved later - make sure to store it in a safe place.
        The application password can be used to authenticate against the API instead of the regular password.
        It does not require 2FA verification. Generating a new application password will invalidate all currently active sessions.
        Note that this endpoint only generates an application password accompanied by its hash. To make this new password effective,
        the returned hash has to be set as webserver.api.app_password in the Pi-hole configuration in a follow-up step.
        This can be done in various ways, e.g. via the API (PATCH /api/config/webserver/api/app_pwhash),
        the graphical web interface (Settings -> All Settings) or by editing the configuration file directly.
        """
        return (self.api_call(method='GET', endpoint='auth/app'))
    # end def

    def authSessionList(self):
        """
        Purpose: List of all current sessions
        List of all current sessions including their validity and further information about the client such as the IP address and user agent.
        """
        return (self.api_call(method='GET', endpoint='auth/sessions'))
    # end def

    def authSessionDelete(self, id: int = 0):
        """
        Purpose: Delete session by ID
        Using this endpoint, a session can be deleted by its ID.
        """
        return (self.api_call(method='DELETE', endpoint='auth/session/'+str(id)))
    # end def

    def authNewTOTP(self):
        """
        Purpose: Suggest new TOTP credentials
        Suggest new TOTP credentials for two-factor authentication (2FA)
        """
        return (self.api_call(method='GET', endpoint='auth/totp'))
    # end def

    # Metrics
    # Methods used to get usage data from your Pi-hole

    def metricsGetHistory(self):
        """
        Purpose: Get activity graph data
        Request data needed to generate the "Query over last 24 hours" graph.
        The sum of the values in the individual data arrays may be smaller than the total number of queries for the corresponding timestamp.
        The remaining queries are queries that do not fit into the shown categories (e.g. database busy, unknown status queries, etc.).
        """
        return (self.api_call(method='GET', endpoint='history'))
    # end def

    def metricsGetClientHistory(self, number: int = 25):
        """
        Purpose: Get per-client activity graph data
        Request data needed to generate the "Client activity over last 24 hours" graph. This endpoint returns the top N clients,
        sorted by total number of queries within 24 hours. If N is set to 0, all clients will be returned.
        The client name is only available if the client's IP address can be resolved to a hostname.
        The last client returned is a special client that contains the total number of queries that were not sent by any of the other shown clients ,
        i.e. queries that were sent by clients that are not in the top N. This client is always present,
        even if it has 0 queries and can be identified by the special name "other clients" (mind the space in the hostname) and the IP address "0.0.0.0".
        Note that, due to privacy settings, the returned data may also be empty.
        """
        return (self.api_call(method='GET', endpoint='history/clients?n='+str(number)))
    # end def



    #############################################################################
    # Old v,5 api compatibility
    #
    # DON'T USE IT IF YOU DON'T HAVE TO
    # It is doing a lot of api calls that take a lot of time and resources
    #############################################################################

    # Refreshes statistics
    def refresh(self):
        data = self.api_call(method='GET', endpoint='stats/summary')

        if self.session:
            topdevicedata = self.api_call('GET', 'stats/top_clients', json='{ "blocked": False, "count": 25 }')
            self.top_devices = topdevicedata["top_sources"]
            self.forward_destinations = requests.get("http://" + self.ip_address + "/admin/api.php?getForwardDestinations&auth=" + self.session.token).json()
            self.query_types = requests.get("http://" + self.ip_address + "/admin/api.php?getQueryTypes&auth=" + self.session.token).json()["querytypes"]

        # Data that is returned is now parsed into vars
        self.status = self.api_call('GET', 'dns/blocking')['blocking'] # returns True or False
        self.domain_count = rawdata["domains_being_blocked"]
        self.queries = rawdata["dns_queries_today"]
        self.blocked = rawdata["ads_blocked_today"]
        self.ads_percentage = rawdata["ads_percentage_today"]
        self.unique_domains = rawdata["unique_domains"]
        self.forwarded = rawdata["queries_forwarded"]
        self.cached = rawdata["queries_cached"]
        self.total_clients = rawdata["clients_ever_seen"]
        self.unique_clients = rawdata["unique_clients"]
        self.total_queries = rawdata["dns_queries_all_types"]
        self.gravity_last_updated = rawdata["gravity_last_updated"]

    @requires_auth
    def refreshTop(self, count):
        rawdata = requests.get("http://" + self.ip_address + "/admin/api.php?topItems="+ str(count) +"&auth=" + self.session.token).json()
        self.top_queries = rawdata["top_queries"]
        self.top_ads = rawdata["top_ads"]

    def getGraphData(self):
        rawdata = requests.get("http://" + self.ip_address + "/admin/api.php?overTimeData10mins").json()
        return {"domains":rawdata["domains_over_time"], "ads":rawdata["ads_over_time"]}

    def authenticate(self, password):
        return(self.auth_set(password))

    @requires_auth
    def getAllQueries(self, client=None, domain=None, date_from=None, date_to=None, return_type='raw'):
        """
        This function allows querying the pihole DB. It can take client, domain or dates.
        dates can come in one of the following formats:
            ISO formatted string
            an instance of datetime
            one of the shorthand strings listed above under 'known_time_ranges'

        The return type can be either returned as is (default) or formatted (return_type=array_dict) in order to make
        using the data easier
        """
        if self.session == None:
            print("Unable to get queries. Please authenticate")
            exit(1)

        url = "http://" + self.ip_address + "/admin/api_db.php?getAllQueries&auth=" + self.session.token

        if client and domain:
            print("Cannot search for both client AND domain")
            exit(1)

        start = None
        until = None
        if isinstance(date_from, str):
            try:
                start = date_parser.isoparse(date_from)
            except Exception:
                if date_from in self.known_time_ranges and date_to is None:
                    start, until = self.known_time_ranges[date_from]
        elif isinstance(date_from, dt.datetime):
            start = date_from

        if isinstance(date_to, str):
            try:
                until = date_parser.isoparse(date_to)
            except Exception:
                pass
        elif isinstance(date_from, dt.datetime):
            until = date_to

        if start is not None:
            url +="&from=" + str(start.timestamp())

        if until is not None:
            url +="&until=" + str(until.timestamp())

        if client:
            url += "&client=" + client

        if domain:
            url += "&domain=" + domain

        result = requests.get(url).json()
        if 'data' not in result:
            raise QueryException("Empty results returned: something is wrong with your query")

        if return_type == 'array_dict':
            data = [{
                'datetime': dt.datetime.fromtimestamp(item[0]),
                'type': item[1],
                'requested_domain': item[2],
                'client': item[3],
                'status': QueryActionType(item[4])
            } for item in result['data']]
        else:
            data = result['data']

        return data

    @requires_auth
    def enable(self):
        requests.get("http://" + self.ip_address + "/admin/api.php?enable&auth=" + self.session.token)

    @requires_auth
    def disable(self, seconds):
        requests.get("http://" + self.ip_address + "/admin/api.php?disable="+ str(seconds) +"&auth=" + self.session.token)
    # end def

    def getVersion(self):
        return requests.get("http://" + self.ip_address + "/admin/api.php?versions").json()

    @requires_auth
    def getDBfilesize(self):
        return float(requests.get("http://" + self.ip_address + "/admin/api_db.php?getDBfilesize&auth=" + self.session.token).json()["filesize"])

    @requires_auth
    def getList(self, list):
        return requests.get(
            "http://" + str(self.ip_address) + "/admin/api.php?list=" + list + "&auth=" + self.session.token).json()

    @requires_auth
    def add(self, list, domain, comment=""):
        url = "/admin/api.php?list=" + list + "&add=" + domain + "&auth=" + self.session.token
        comment = {'comment': comment}
        response = requests.post(
            "http://" + str(self.ip_address) + url, data=comment)
        return response.text

    @requires_auth
    def sub(self, list, domain):
        with requests.session() as s:
            s.get("http://"+ str(self.ip_address) +"/admin/scripts/pi-hole/php/sub.php")
            requests.post("http://"+ str(self.ip_address) +"/admin/scripts/pi-hole/php/sub.php", data={"list":list, "domain":domain, "pw":self.password}).text
