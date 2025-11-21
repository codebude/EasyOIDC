from fastapi import Request
from fastapi.responses import RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.routing import Route
from EasyOIDC import OIDClient, Config
from EasyOIDC.utils import is_path_matched
from EasyOIDC.session import SessionHandler
from EasyOIDC.frameworks import SESSION_STATE_VAR_NAME, REFERRER_VAR_NAME
from nicegui.app import App
from nicegui import app
import logging


class NiceGUIOIDClient(OIDClient):
    logger = logging.getLogger(__name__)

    def __init__(self, nicegui_app: App, auth_config: Config = None, session_storage: SessionHandler = None,
                 log_enabled: bool = True, **kwargs):
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
        self._nicegui_app.add_middleware(auth_middleware)

        self.set_redirector(lambda url: RedirectResponse(url))

        # Roles getter that safely accesses app.storage.user only in UI context
        def get_roles():
            try:
                state = app.storage.user.get(SESSION_STATE_VAR_NAME, '')
                if state and state in self._session_storage:
                    return self._session_storage[state].get('userinfo', {}).get('realm_access', {}).get('roles', [])
            except RuntimeError:
                # Not in UI context, return empty roles
                pass
            return []
        
        self.set_roles_getter(get_roles)

        # Add FastAPI route /login to method login_route_handler
        self._nicegui_app.add_route(auth_config.app_login_route, self._login_route_handler)

        # Add FastAPI route /authorize to method authorize_route_handler
        self._nicegui_app.add_route(auth_config.app_authorize_route, self._authorize_route_handler)

        # Add FastAPI route /logout to method logout_route_handler
        self._nicegui_app.add_route(auth_config.app_logout_route, self._logout_route_handler)

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
            samesite='lax'
        )
        # Clear referrer cookie
        response.delete_cookie(REFERRER_VAR_NAME)
        
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
            samesite='lax'
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

    def is_authenticated(self):
        try:
            state = app.storage.user.get(SESSION_STATE_VAR_NAME, None)
            if state and (state in self._session_storage) and (self._session_storage[state]['userinfo']):
                return True
        except RuntimeError:
            # Not in UI context, cannot determine authentication state
            pass
        return False

    def get_userinfo(self):
        try:
            state = app.storage.user.get(SESSION_STATE_VAR_NAME, None)
            if state and (state in self._session_storage) and (self._session_storage[state]['userinfo']):
                return self._session_storage[state]['userinfo']
        except RuntimeError:
            # Not in UI context, cannot get userinfo
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

        if not authenticated:
            if session_state and (session_state in self.session_storage):
                del self.session_storage[session_state]
            # Check if the requested path matches with unrestricted_page_routes.
            if not page_unrestricted:
                path_without_domain = request.url.path + ('?' + request.url.query if request.url.query else '')
                # Store referrer in cookie instead of app.storage.user
                response = RedirectResponse(login_route)
                response.set_cookie(
                    key=REFERRER_VAR_NAME,
                    value='/' if path_without_domain is None else path_without_domain,
                    httponly=True,
                    samesite='lax'
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
        
        # Sync session state to app.storage.user for UI context
        response = await call_next(request)
        
        # If this is a UI page request and we have a session, sync to app.storage.user
        if session_state and authenticated:
            try:
                app.storage.user[SESSION_STATE_VAR_NAME] = session_state
            except RuntimeError:
                # Not in UI context yet, that's okay
                pass
        
        return response
