"""
This module provides WSGI application to serve the Home Assistant API.

For more details about this component, please refer to the documentation at
https://home-assistant.io/components/http/
"""
import asyncio
import hmac
import json
import logging
import os
from pathlib import Path
import re
import ssl
from ipaddress import ip_address, ip_network

import voluptuous as vol
from aiohttp import web
from aiohttp.file_sender import FileSender
from aiohttp.web_exceptions import HTTPUnauthorized, HTTPMovedPermanently

from homeassistant.core import callback, is_callback
import homeassistant.remote as rem
from homeassistant import util
from homeassistant.const import (
    SERVER_PORT, HTTP_HEADER_HA_AUTH,  # HTTP_HEADER_CACHE_CONTROL,
    CONTENT_TYPE_JSON, ALLOWED_CORS_HEADERS, EVENT_HOMEASSISTANT_STOP,
    EVENT_HOMEASSISTANT_START)
import homeassistant.helpers.config_validation as cv
from homeassistant.components import persistent_notification

DOMAIN = 'http'
REQUIREMENTS = ('aiohttp_cors==0.4.0',)

CONF_API_PASSWORD = 'api_password'
CONF_SERVER_HOST = 'server_host'
CONF_SERVER_PORT = 'server_port'
CONF_DEVELOPMENT = 'development'
CONF_SSL_CERTIFICATE = 'ssl_certificate'
CONF_SSL_KEY = 'ssl_key'
CONF_CORS_ORIGINS = 'cors_allowed_origins'
CONF_TRUSTED_NETWORKS = 'trusted_networks'

DATA_API_PASSWORD = 'api_password'
NOTIFICATION_ID_LOGIN = 'http-login'

# TLS configuation follows the best-practice guidelines specified here:
# https://wiki.mozilla.org/Security/Server_Side_TLS
# Intermediate guidelines are followed.
SSL_VERSION = ssl.PROTOCOL_SSLv23
SSL_OPTS = ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3
if hasattr(ssl, 'OP_NO_COMPRESSION'):
    SSL_OPTS |= ssl.OP_NO_COMPRESSION
CIPHERS = "ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:" \
          "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:" \
          "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:" \
          "DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384:" \
          "ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA256:" \
          "ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:" \
          "ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES256-SHA384:" \
          "ECDHE-ECDSA-AES256-SHA:ECDHE-RSA-AES256-SHA:" \
          "DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-RSA-AES256-SHA256:" \
          "DHE-RSA-AES256-SHA:ECDHE-ECDSA-DES-CBC3-SHA:" \
          "ECDHE-RSA-DES-CBC3-SHA:EDH-RSA-DES-CBC3-SHA:AES128-GCM-SHA256:" \
          "AES256-GCM-SHA384:AES128-SHA256:AES256-SHA256:AES128-SHA:" \
          "AES256-SHA:DES-CBC3-SHA:!DSS"

_FINGERPRINT = re.compile(r'^(.+)-[a-z0-9]{32}\.(\w+)$', re.IGNORECASE)

_LOGGER = logging.getLogger(__name__)

CONFIG_SCHEMA = vol.Schema({
    DOMAIN: vol.Schema({
        vol.Optional(CONF_API_PASSWORD): cv.string,
        vol.Optional(CONF_SERVER_HOST): cv.string,
        vol.Optional(CONF_SERVER_PORT, default=SERVER_PORT):
            vol.All(vol.Coerce(int), vol.Range(min=1, max=65535)),
        vol.Optional(CONF_DEVELOPMENT): cv.string,
        vol.Optional(CONF_SSL_CERTIFICATE): cv.isfile,
        vol.Optional(CONF_SSL_KEY): cv.isfile,
        vol.Optional(CONF_CORS_ORIGINS): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional(CONF_TRUSTED_NETWORKS):
            vol.All(cv.ensure_list, [ip_network])
    }),
}, extra=vol.ALLOW_EXTRA)


# TEMP TO GET TESTS TO RUN
def request_class():
    """."""
    raise Exception('not implemented')


class HideSensitiveFilter(logging.Filter):
    """Filter API password calls."""

    # pylint: disable=too-few-public-methods
    def __init__(self, hass):
        """Initialize sensitive data filter."""
        super().__init__()
        self.hass = hass

    def filter(self, record):
        """Hide sensitive data in messages."""
        if self.hass.wsgi.api_password is None:
            return True

        record.msg = record.msg.replace(self.hass.wsgi.api_password, '*******')

        return True


def setup(hass, config):
    """Set up the HTTP API and debug interface."""
    logging.getLogger('aiohttp.access').addFilter(HideSensitiveFilter(hass))

    conf = config.get(DOMAIN, {})

    api_password = util.convert(conf.get(CONF_API_PASSWORD), str)
    server_host = conf.get(CONF_SERVER_HOST, '0.0.0.0')
    server_port = conf.get(CONF_SERVER_PORT, SERVER_PORT)
    development = str(conf.get(CONF_DEVELOPMENT, '')) == '1'
    ssl_certificate = conf.get(CONF_SSL_CERTIFICATE)
    ssl_key = conf.get(CONF_SSL_KEY)
    cors_origins = conf.get(CONF_CORS_ORIGINS, [])
    trusted_networks = [
        ip_network(trusted_network)
        for trusted_network in conf.get(CONF_TRUSTED_NETWORKS, [])]

    server = HomeAssistantWSGI(
        hass,
        development=development,
        server_host=server_host,
        server_port=server_port,
        api_password=api_password,
        ssl_certificate=ssl_certificate,
        ssl_key=ssl_key,
        cors_origins=cors_origins,
        trusted_networks=trusted_networks
    )

    @callback
    def start_server(event):
        hass.loop.create_task(server.start())

    hass.bus.listen_once(EVENT_HOMEASSISTANT_START, start_server)

    @callback
    def stop_server(event):
        hass.loop.create_task(server.stop())

    hass.bus.listen_once(EVENT_HOMEASSISTANT_STOP, stop_server)

    hass.wsgi = server
    hass.config.api = rem.API(server_host if server_host != '0.0.0.0'
                              else util.get_local_ip(),
                              api_password, server_port,
                              ssl_certificate is not None)

    return True


class HomeAssistantWSGI(object):
    """WSGI server for Home Assistant."""

    # pylint: disable=too-many-instance-attributes, too-many-locals
    # pylint: disable=too-many-arguments

    def __init__(self, hass, development, api_password, ssl_certificate,
                 ssl_key, server_host, server_port, cors_origins,
                 trusted_networks):
        """Initilalize the WSGI Home Assistant server."""
        import aiohttp_cors

        self.app = web.Application(loop=hass.loop)
        self.hass = hass
        self.development = development
        self.api_password = api_password
        self.ssl_certificate = ssl_certificate
        self.ssl_key = ssl_key
        self.server_host = server_host
        self.server_port = server_port
        self.trusted_networks = trusted_networks
        self.event_forwarder = None
        self.server = None

        if cors_origins:
            self.cors = aiohttp_cors.setup(self.app, defaults={
                host: aiohttp_cors.ResourceOptions(
                    allow_headers=ALLOWED_CORS_HEADERS,
                    allow_methods='*',
                ) for host in cors_origins
            })
        else:
            self.cors = None

        if development:
            try:
                import aiohttp_debugtoolbar
                aiohttp_debugtoolbar.setup(self.app)
            except ImportError:
                pass

    def register_view(self, view):
        """Register a view with the WSGI server.

        The view argument must be a class that inherits from HomeAssistantView.
        It is optional to instantiate it before registering; this method will
        handle it either way.
        """
        if isinstance(view, type):
            # Instantiate the view, if needed
            view = view(self.hass)

        urls = [view.url] + view.extra_urls

        for method in ('get', 'post', 'delete', 'put'):
            handler = getattr(view, method, None)

            if not handler:
                continue

            handler = request_handler_factory(view, handler)

            for url in urls:
                self.app.router.add_route(method, url, handler)

        # Sadly, aiohttp_cors cannot work with class based views
        # self.app.router.add_route('*', view.url, view, name=view.name)

        # for url in view.extra_urls:
        #     self.app.router.add_route('*', url, view)

    def register_redirect(self, url, redirect_to):
        """Register a redirect with the server.

        If given this must be either a string or callable. In case of a
        callable it's called with the url adapter that triggered the match and
        the values of the URL as keyword arguments and has to return the target
        for the redirect, otherwise it has to be a string with placeholders in
        rule syntax.
        """

        def redirect(request):
            """Redirect to location."""
            raise HTTPMovedPermanently(redirect_to)

        self.app.router.add_route('GET', url, redirect)

    def register_static_path(self, url_root, path, cache_length=31):
        """Register a folder to serve as a static path.

        Specify optional cache length of asset in days.
        """
        # TODO - TEMPORARY WORKAROUND, DOES NOT SUPPORT GZIP
        if os.path.isdir(path):
            self.app.router.add_static(url_root, path)
            return

        @asyncio.coroutine
        def serve_file(request):
            """Redirect to location."""
            return FileSender().send(request, Path(path))

        self.app.router.add_route('GET', url_root, serve_file)

        # Cache static while not in development
        # if cache_length and not self.development:
        #     # 1 year in seconds
        #     cache_time = cache_length * 86400

        #     headers.append({
        #         'prefix': '',
        #         HTTP_HEADER_CACHE_CONTROL:
        #         "public, max-age={}".format(cache_time)
        #     })

    @asyncio.coroutine
    def start(self):
        """Start the wsgi server."""
        if self.cors is not None:
            for route in list(self.app.router.routes()):
                self.cors.add(route)

        if self.ssl_certificate:
            context = ssl.SSLContext(SSL_VERSION)
            context.options |= SSL_OPTS
            context.set_ciphers(CIPHERS)
            context.load_cert_chain(self.ssl_certificate, self.ssl_key)
        else:
            context = None

        self._handler = self.app.make_handler()
        self.server = yield from self.hass.loop.create_server(
            self._handler, self.server_host, self.server_port, ssl=context)

    @asyncio.coroutine
    def stop(self):
        """Stop the wsgi server."""
        self.server.close()
        yield from self.server.wait_closed()
        yield from self.app.shutdown()
        yield from self._handler.finish_connections(60.0)
        yield from self.app.cleanup()

    @staticmethod
    def get_real_ip(request):
        """Return the clients correct ip address, even in proxied setups."""
        peername = request.transport.get_extra_info('peername')
        return peername[0] if peername is not None else None

    def is_trusted_ip(self, remote_addr):
        """Match an ip address against trusted CIDR networks."""
        return any(ip_address(remote_addr) in trusted_network
                   for trusted_network in self.hass.wsgi.trusted_networks)


class HomeAssistantView(object):
    """Base view for all views."""

    extra_urls = []
    requires_auth = True  # Views inheriting from this class can override this

    def __init__(self, hass):
        """Initilalize the base view."""
        if not hasattr(self, 'url'):
            class_name = self.__class__.__name__
            raise AttributeError(
                '{0} missing required attribute "url"'.format(class_name)
            )

        if not hasattr(self, 'name'):
            class_name = self.__class__.__name__
            raise AttributeError(
                '{0} missing required attribute "name"'.format(class_name)
            )

        self.hass = hass

    @callback
    def options(self, request):
        """Default options handler for CORS."""
        return web.Response(status=200)

    def json(self, result, status_code=200):
        """Return a JSON response."""
        msg = json.dumps(
            result, sort_keys=True, cls=rem.JSONEncoder).encode('UTF-8')
        return web.Response(
            body=msg, content_type=CONTENT_TYPE_JSON, status=status_code)

    def json_message(self, error, status_code=200):
        """Return a JSON message response."""
        return self.json({'message': error}, status_code)

    def file(self, request, fil):
        """Return a file."""
        assert isinstance(fil, str), 'only string paths allowed'
        return FileSender().send(request, Path(fil))


def request_handler_factory(view, handler):
    """Factory to wrap our handler classes.

    Eventually authentication should be managed by middleware.
    """
    @asyncio.coroutine
    def handle(request):
        """Handle incoming request."""
        remote_addr = HomeAssistantWSGI.get_real_ip(request)

        # Auth code verbose on purpose
        authenticated = False

        if view.hass.wsgi.api_password is None:
            authenticated = True

        elif view.hass.wsgi.is_trusted_ip(remote_addr):
            authenticated = True

        elif hmac.compare_digest(request.headers.get(HTTP_HEADER_HA_AUTH, ''),
                                 view.hass.wsgi.api_password):
            # A valid auth header has been set
            authenticated = True

        elif hmac.compare_digest(request.GET.get(DATA_API_PASSWORD, ''),
                                 view.hass.wsgi.api_password):
            authenticated = True

        if view.requires_auth and not authenticated:
            _LOGGER.warning('Login attempt or request with an invalid '
                            'password from %s', remote_addr)
            persistent_notification.async_create(
                view.hass,
                'Invalid password used from {}'.format(remote_addr),
                'Login attempt failed', NOTIFICATION_ID_LOGIN)
            raise HTTPUnauthorized()

        request.authenticated = authenticated

        _LOGGER.info('Serving %s to %s (auth: %s)',
                     request.path, remote_addr, authenticated)

        assert asyncio.iscoroutinefunction(handler) or is_callback(handler), \
            "Handler should be a coroutine or a callback."

        result = handler(request, **request.match_info)

        if asyncio.iscoroutine(result):
            result = yield from result

        if isinstance(result, web.StreamResponse):
            # The method handler returned a ready-made Response, how nice of it
            return result

        status_code = 200

        if isinstance(result, tuple):
            result, status_code = result

        if isinstance(result, str):
            result = result.encode('utf-8')
        elif result is None:
            result = b''
        elif not isinstance(result, bytes):
            assert False, ('Result should be None, string, bytes or Response. '
                           'Got: {}').format(result)

        return web.Response(body=result, status=status_code)

    return handle
