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
from aiohttp.errors import HttpMethodNotAllowed
from aiohttp.web_exceptions import HTTPUnauthorized, HTTPMovedPermanently

from homeassistant.core import callback, is_callback
import homeassistant.remote as rem
from homeassistant import util
from homeassistant.const import (
    SERVER_PORT, HTTP_HEADER_HA_AUTH, HTTP_HEADER_CACHE_CONTROL,
    HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN, CONTENT_TYPE_JSON,
    HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS, ALLOWED_CORS_HEADERS,
    EVENT_HOMEASSISTANT_STOP, EVENT_HOMEASSISTANT_START)
from homeassistant.core import split_entity_id
import homeassistant.helpers.config_validation as cv
from homeassistant.components import persistent_notification

DOMAIN = 'http'

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

    # @callback
    def start_server(event):
        # hass.loop.create_task(server.start())

        # Temp, while fixing listen_once
        from homeassistant.util.async import run_coroutine_threadsafe

        run_coroutine_threadsafe(server.start(), hass.loop).result()

    hass.bus.listen_once(EVENT_HOMEASSISTANT_START, start_server)

    # @callback
    def stop_server(event):
        # hass.loop.create_task(server.stop)

        # Temp, while fixing listen_once
        from homeassistant.util.async import run_coroutine_threadsafe

        run_coroutine_threadsafe(server.stop(), hass.loop).result()

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
        self.app = web.Application(loop=hass.loop)
        self.hass = hass
        self.development = development
        self.api_password = api_password
        self.ssl_certificate = ssl_certificate
        self.ssl_key = ssl_key
        self.server_host = server_host
        self.server_port = server_port
        self.cors_origins = cors_origins
        self.trusted_networks = trusted_networks
        self.event_forwarder = None
        self.server = None

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

        self.app.router.add_route('*', view.url, view, name=view.name)

        for url in view.extra_urls:
            self.app.router.add_route('*', url, view)

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

        # http://aiohttp.readthedocs.io/en/stable/web.html#static-file-handling

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
        self._handler = self.app.make_handler()
        self.server = yield from self.hass.loop.create_server(
            self._handler, self.server_host, self.server_port)

        # TODO SSL

    @asyncio.coroutine
    def stop(self):
        """Stop the wsgi server."""
        self.server.close()
        yield from self.server.wait_closed()
        yield from self.app.shutdown()
        yield from self._handler.finish_connections(60.0)
        yield from self.app.cleanup()

    # def base_app(self, environ, start_response):
    #     """WSGI Handler of requests to base app."""
    #     request = self.Request(environ)
    #     response = self.dispatch_request(request)

    #     if self.cors_origins:
    #         cors_check = (environ.get('HTTP_ORIGIN') in self.cors_origins)
    #         cors_headers = ", ".join(ALLOWED_CORS_HEADERS)
    #         if cors_check:
    #             response.headers[HTTP_HEADER_ACCESS_CONTROL_ALLOW_ORIGIN] = \
    #                 environ.get('HTTP_ORIGIN')
    #             response.headers[HTTP_HEADER_ACCESS_CONTROL_ALLOW_HEADERS] = \
    #                 cors_headers

    #     return response(environ, start_response)

    @staticmethod
    def get_real_ip(request):
        """Return the clients correct ip address, even in proxied setups."""
        # if request.access_route:
        #     return request.access_route[-1]
        # else:
        # return request.remote_addr
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

    def options(self, request):
        """Default handler for OPTIONS (necessary for CORS preflight)."""
        # TODO CORS ?
        return web.Response('', status=200)

    def __call__(self, request):
        """Handle incoming request."""
        try:
            handler = getattr(self, request.method.lower())
        except AttributeError:
            raise HttpMethodNotAllowed()

        remote_addr = HomeAssistantWSGI.get_real_ip(request)

        # Auth code verbose on purpose
        authenticated = False

        if self.hass.wsgi.api_password is None:
            authenticated = True

        elif self.hass.wsgi.is_trusted_ip(remote_addr):
            authenticated = True

        elif hmac.compare_digest(request.headers.get(HTTP_HEADER_HA_AUTH, ''),
                                 self.hass.wsgi.api_password):
            # A valid auth header has been set
            authenticated = True

        elif hmac.compare_digest(request.GET.get(DATA_API_PASSWORD, ''),
                                 self.hass.wsgi.api_password):
            authenticated = True

        if self.requires_auth and not authenticated:
            _LOGGER.warning('Login attempt or request with an invalid '
                            'password from %s', remote_addr)
            persistent_notification.async_create(
                self.hass,
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
