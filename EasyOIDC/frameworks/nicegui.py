from fastapi import Request, FastAPI
from fastapi.responses import RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route
from EasyOIDC import OIDClient, Config
from EasyOIDC.utils import is_path_matched
from EasyOIDC.session import SessionHandler
from EasyOIDC.frameworks import SESSION_STATE_VAR_NAME, REFERRER_VAR_NAME
from nicegui.app import App
from nicegui import app
import contextvars

# Context variable to hold the current Request during middleware processing so
# `NiceGUIOIDClient.is_authenticated()` and `get_userinfo()` can access the request
# in non-UI contexts without requiring the caller to pass it explicitly.
CURRENT_REQUEST: contextvars.ContextVar[Request] = contextvars.ContextVar('CURRENT_REQUEST', default=None)
import logging


class NiceGUIOIDClient(OIDClient):
    logger = logging.getLogger(__name__)

    def __init__(self, nicegui_app: App, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True, fastapi_app: FastAPI = None, **kwargs):
        if auth_config is None:
            auth_config = Config('.env')
        if session_storage is None:
            session_storage = SessionHandler(mode='shelve')

        super().__init__(auth_config, log_enabled)
        self._auth_config = auth_config
        self._session_storage = session_storage
        self._nicegui_app = nicegui_app

        if 'unrestricted_routes' in kwargs:
            self._auth_config.unrestricted_routes = kwargs['unrestricted_routes']
        else:
            # Get all routes from nicegui app
            nicegui_routes = ([r.path.replace('{key:path}', '*').replace('{key}/{path:path}', '*') for r in
                              nicegui_app.routes if (type(r) == Route) or (r.path.startswith('/_nicegui'))] +
                              ['/_nicegui/*'])
            self._auth_config.unrestricted_routes += nicegui_routes

        if 'logger' in kwargs:
            self.logger = kwargs['logger']

        auth_middleware = AuthMiddleware
        auth_middleware.logger = self.logger
        auth_middleware.session_storage = session_storage
        auth_middleware.oidc_client = self
        auth_middleware.log_enabled = log_enabled
        auth_middleware.nicegui_app = nicegui_app
        # register middleware in NiceGUI app
        self._nicegui_app.add_middleware(auth_middleware)
        # also register middleware in the provided FastAPI app (if any) so native handlers
        # go through the same middleware logic and we can leverage set request.state etc.
        if fastapi_app is not None:
            try:
                fastapi_app.add_middleware(auth_middleware)
                if self.logger:
                    self.logger.debug('AuthMiddleware registered on provided FastAPI app.')
            except Exception as e:
                if self.logger:
                    self.logger.debug(f'Unable to register AuthMiddleware on provided FastAPI app: {e}')

        self.set_redirector(lambda url: RedirectResponse(url))

        # Roles getter that safely accesses app.storage.user only in UI context
        def get_roles(request: Request = None):
            # First, try UI context
            try:
                state = app.storage.user.get(SESSION_STATE_VAR_NAME, '')
                if state and state in self._session_storage:
                    return self._session_storage[state].get('userinfo', {}).get('realm_access', {}).get('roles', [])
            except RuntimeError:
                # Not in UI context, continue to fallback
                pass

            # If no request is provided, try to retrieve it from context var
            if request is None:
                try:
                    request = CURRENT_REQUEST.get()
                except Exception:
                    request = None

            if request is not None:
                # prefer request.state.userinfo
                if hasattr(request, 'state') and getattr(request.state, 'userinfo', None):
                    userinfo = request.state.userinfo
                    return userinfo.get('realm_access', {}).get('roles', []) if userinfo else []
                # fallback to cookie based session state
                try:
                    state = request.cookies.get(SESSION_STATE_VAR_NAME, None)
                    if state and state in self._session_storage:
                        return self._session_storage[state].get('userinfo', {}).get('realm_access', {}).get('roles', [])
                except Exception:
                    pass

            # no roles available
            return []
        
        self.set_roles_getter(get_roles)

        # Add FastAPI route /login to method login_route_handler
        self._nicegui_app.add_route(auth_config.app_login_route, self._login_route_handler)

        # Add FastAPI route /authorize to method authorize_route_handler
        self._nicegui_app.add_route(auth_config.app_authorize_route, self._authorize_route_handler)

        # Add FastAPI route /logout to method logout_route_handler
        self._nicegui_app.add_route(auth_config.app_logout_route, self._logout_route_handler)

        # Register a handler to initialize UI storage when a new websocket client connects
        try:
            # The on_connect hook is provided by NiceGUI and will be called in UI/websocket context
            self._nicegui_app.on_connect(self._on_connect_handler)
            # Also hook disconnect to cleanup optional UI storage
            try:
                self._nicegui_app.on_disconnect(self._on_disconnect_handler)
            except Exception:
                # not all NiceGUI versions expose on_disconnect; ignore if missing
                pass
        except Exception:
            # If the app does not expose on_connect, skip silently; fallback remains cookies
            pass

    def set_logger(self, logger):
        self.logger = logger

    def _authorize_route_handler(self, request: Request) -> Response:
        try:
            state = request.query_params['state']
            # Get state from cookie instead of app.storage.user
            cookie_state = request.cookies.get(SESSION_STATE_VAR_NAME, None)
            assert state == cookie_state

            token, oauth_session = self.get_token(str(request.url))
            userinfo = self.get_user_info(oauth_session)
            self._session_storage[state] = {'userinfo': userinfo, 'token': dict(token)}

            if self._log_enabled:
                self.logger.debug('Authentication successful.')
        except Exception as e:
            if self._log_enabled:
                self.logger.debug(f"Authentication error: '{e}'. Redirecting to login page...")
            return RedirectResponse(self._auth_config.app_login_route)

        # Get referrer from cookie instead of app.storage.user
        referrer_path = request.cookies.get(REFERRER_VAR_NAME, '')
        response = RedirectResponse(referrer_path if referrer_path else '/')
        
        # Set session state cookie
        response.set_cookie(
            key=SESSION_STATE_VAR_NAME,
            value=state,
            httponly=True,
            samesite='lax',
            path='/'
        )
        # Clear referrer cookie
        response.delete_cookie(REFERRER_VAR_NAME)
        
        # Try to update connected UI clients' storage.user with the new session state.
        # Not all NiceGUI versions expose a clients collection; attempt multiple ways gracefully.
        try:
            clients = getattr(self._nicegui_app, 'clients', None) or getattr(app, 'clients', None)
            if clients:
                # clients might be a dict or list of Client objects
                iterable = clients.values() if isinstance(clients, dict) else clients
                for client in iterable:
                    try:
                        # many client objects expose `storage` property
                        if hasattr(client, 'storage') and hasattr(client.storage, 'user'):
                            client.storage.user[SESSION_STATE_VAR_NAME] = state
                            if self.logger:
                                self.logger.debug(f"Authorize: set client.storage.user[{SESSION_STATE_VAR_NAME}]={state}")
                    except Exception:
                        # fall back to global app; might still raise if not in UI context
                        try:
                            app.storage.user[SESSION_STATE_VAR_NAME] = state
                        except Exception:
                            pass
        except Exception:
            # Silently ignore if clients aren't accessible
            pass

        return response

    def _login_route_handler(self, request: Request) -> Response:
        uri, state = self.auth_server_login()
        self._session_storage[state] = {'userinfo': None, 'token': None}
        
        # Store state in cookie instead of app.storage.user
        response = RedirectResponse(uri)
        response.set_cookie(
            key=SESSION_STATE_VAR_NAME,
            value=state,
            httponly=True,
            samesite='lax',
            path='/'
        )
        return response

    def _get_current_token(self, state=None):
        if state is None:
            # Try to get from UI context
            try:
                state = app.storage.user.get(SESSION_STATE_VAR_NAME, '')
            except RuntimeError:
                # Not in UI context
                return None
        if state and state in self._session_storage:
            return self._session_storage[state]['token']
        return None

    async def _on_connect_handler(self, client):
        """Initialize `app.storage.user` for the connecting client based on cookies.
        This runs in a UI/websocket context where `app.storage.user` is available.
        """
        # Attempt to read cookies from the websocket handshake request headers
        try:
            cookies_header = None
            # Client may expose `request.headers` in different versions
            if hasattr(client, 'request') and hasattr(client.request, 'headers'):
                cookies_header = client.request.headers.get('cookie', '')
            elif hasattr(client, 'scope') and isinstance(client.scope, dict):
                # headers are as list of tuples in scope
                headers = dict((k.decode('latin1'), v.decode('latin1')) for k, v in client.scope.get('headers', []))
                cookies_header = headers.get('cookie', '')
            elif hasattr(client, 'headers'):
                cookies_header = client.headers.get('cookie', '')

            if cookies_header:
                from http.cookies import SimpleCookie
                cookie = SimpleCookie()
                cookie.load(cookies_header)
                if SESSION_STATE_VAR_NAME in cookie:
                    state = cookie[SESSION_STATE_VAR_NAME].value
                    # Sync this client's storage.user
                    try:
                        app.storage.user[SESSION_STATE_VAR_NAME] = state
                        if self.logger:
                            self.logger.debug(f"On connect: set app.storage.user[{SESSION_STATE_VAR_NAME}]={state}")
                    except Exception:
                        # If the UI runtime throws (unlikely in on_connect), ignore
                        pass
                else:
                    if self.logger:
                        self.logger.debug('On connect: no session-state cookie present')
        except Exception:
            # If any of the above fails, don't break the websocket connection
            pass

    async def _on_disconnect_handler(self, client):
        """Clear `app.storage.user` for the disconnecting client to avoid stale data."""
        try:
            # Only attempt to clear UI storage (available in websocket context)
            try:
                app.storage.user[SESSION_STATE_VAR_NAME] = None
            except Exception:
                # App may not support storage updates in this NiceGUI version
                pass
        except Exception:
            pass

    def _logout(self, state):
        logout_url = None
        token = self._get_current_token(state)
        if token:
            if self._auth_config.logout_endpoint:
                logout_url = self.get_logout_url(token.get('id_token', None))
            if state in self._session_storage:
                del self._session_storage[state]
        return logout_url

    def _logout_route_handler(self, request: Request) -> Response:
        state = request.cookies.get(SESSION_STATE_VAR_NAME, None)
        logout_url = self._logout(state)
        
        response = RedirectResponse(logout_url if logout_url else self._auth_config.post_logout_uri)
        # Clear cookies
        response.delete_cookie(SESSION_STATE_VAR_NAME)
        response.delete_cookie(REFERRER_VAR_NAME)
        
        return response

    def is_authenticated(self, request: Request = None):
        try:
            state = app.storage.user.get(SESSION_STATE_VAR_NAME, None)
            if state and (state in self._session_storage) and (self._session_storage[state]['userinfo']):
                return True
        except RuntimeError:
            # Not in UI context, cannot determine authentication state
            pass
        # Fallback: determine the Request either from the provided parameter, the
        # CURRENT_REQUEST context var (set by middleware), or None
        if request is None:
            try:
                request = CURRENT_REQUEST.get()
            except Exception:
                request = None
        # Fallback: if a request is available, check request.state.userinfo, then cookies
        try:
            if request is not None:
                # Prefer the request.state set by middleware
                if hasattr(request, 'state') and getattr(request.state, 'userinfo', None):
                    return True
                state = request.cookies.get(SESSION_STATE_VAR_NAME, None)
                if state and (state in self._session_storage) and (self._session_storage[state]['userinfo']):
                    return True
        except Exception:
            pass
        return False

    def get_userinfo(self, request: Request = None):
        try:
            state = app.storage.user.get(SESSION_STATE_VAR_NAME, None)
            if state and (state in self._session_storage) and (self._session_storage[state]['userinfo']):
                return self._session_storage[state]['userinfo']
        except RuntimeError:
            # Not in UI context, cannot get userinfo
            pass
        # Fallback: determine request source like `is_authenticated` does
        if request is None:
            try:
                request = CURRENT_REQUEST.get()
            except Exception:
                request = None
        # Fallback: check request.state then cookies
        try:
            if request is not None:
                if hasattr(request, 'state') and getattr(request.state, 'userinfo', None):
                    return request.state.userinfo
                state = request.cookies.get(SESSION_STATE_VAR_NAME, None)
                if state and (state in self._session_storage) and (self._session_storage[state]['userinfo']):
                    return self._session_storage[state]['userinfo']
        except Exception:
            pass
        return None


class AuthMiddleware(BaseHTTPMiddleware):
    session_storage = None
    oidc_client = None
    log_enabled = None
    nicegui_app = None
    logger = logging.getLogger(__name__)

    async def dispatch(self, request: Request, call_next):
        authenticated = False
        config = self.oidc_client.get_config()
        # Get session state from cookie instead of app.storage.user
        session_state = request.cookies.get(SESSION_STATE_VAR_NAME, None)
        unrestricted_page_routes = self.oidc_client.get_config().get_unrestricted_routes()
        login_route = config.app_login_route
        page_unrestricted = any(is_path_matched(request.url.path, pattern) for pattern in unrestricted_page_routes)

        if session_state and (session_state in self.session_storage):
            token = self.session_storage[session_state]['token']
            # Verifica la sesión contra el servidor
            authenticated = self.oidc_client.is_valid_oidc_session(self.oidc_client.get_oauth_session(token))
            # Attach session info to the request.state for easier access in downstream handlers
            try:
                request.state.session_state = session_state
                request.state.userinfo = self.session_storage[session_state].get('userinfo')
            except Exception:
                pass

        if not authenticated:
            if session_state and (session_state in self.session_storage):
                del self.session_storage[session_state]
            # Check if the requested path matches with unrestricted_page_routes.
            if not page_unrestricted:
                path_without_domain = request.url.path + ('?' + request.url.query if request.url.query else '')
                # Store referrer in cookie instead of app.storage.user
                response = RedirectResponse(login_route)
                # set referrer cookie with path
                response.set_cookie(
                    key=REFERRER_VAR_NAME,
                    value='/' if path_without_domain is None else path_without_domain,
                    httponly=True,
                    samesite='lax',
                    path='/'
                )
                if self.log_enabled:
                    self.logger.debug(f"After login will redirect to '{path_without_domain}'")
                return response
        else:
            # Check if there's a referrer to redirect to
            referrer_path = request.cookies.get(REFERRER_VAR_NAME, '')
            if referrer_path:
                if self.log_enabled:
                    self.logger.debug('Redirecting to', referrer_path)
                response = RedirectResponse(referrer_path)
                response.delete_cookie(REFERRER_VAR_NAME)
                return response
        
        # Set current request context var for downstream lookups
        token = CURRENT_REQUEST.set(request)
        try:
            # Sync session state to app.storage.user for UI context
            response = await call_next(request)
        finally:
            # Reset context var to previous value
            CURRENT_REQUEST.reset(token)
        
        # If this is a UI page request and we have a session, sync to app.storage.user
        if session_state and authenticated:
            try:
                app.storage.user[SESSION_STATE_VAR_NAME] = session_state
            except RuntimeError:
                # Not in UI context yet, that's okay
                pass
        
        return response
