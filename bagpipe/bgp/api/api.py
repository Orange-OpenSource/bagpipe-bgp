from six.moves import socketserver
import pecan
from oslo_config import cfg
from wsgiref import simple_server

common_opts = [
    cfg.IPOpt("host", default="127.0.0.1",
              help="IP address on which the API server should listen",
              deprecated_name="api_host"),
    cfg.IntOpt("port", default=8082,
               help="Port on which the API server should listen",
               deprecated_name="api_port")
]

cfg.CONF.register_opts(common_opts, "API")


def setup_app(*args, **kwargs):
    config = {
        'server': {
            'port': cfg.CONF.API.port,
            'host': cfg.CONF.API.host,
        },
        'app': {
            'root': 'bagpipe.bgp.api.controllers.RootController',
        }
    }
    pecan_config = pecan.configuration.conf_from_dict(config)

    app = pecan.make_app(
        pecan_config.app.root,
        # debug=True,
        force_canonical=False,
        guess_content_type_from_ext=True
    )

    return app


class ThreadedSimpleServer(socketserver.ThreadingMixIn,
                           simple_server.WSGIServer):
    pass


class PecanAPI(object):

    def __init__(self):

        app = setup_app()

        self.wsgi = simple_server.make_server(
            cfg.CONF.API.host,
            cfg.CONF.API.port,
            app,
            server_class=ThreadedSimpleServer
        )

    def run(self):
        self.wsgi.serve_forever()

    def stop(self):
        # call stop on RootController
        self.wsgi.get_app().application.root.stop()


def main():
    api = PecanAPI()
    api.run()

if __name__ == "__main__":
    main()
