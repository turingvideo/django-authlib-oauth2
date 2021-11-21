from authlib.oauth2 import ClientAuthentication as _ClientAuthentication


class ClientAuthentication(_ClientAuthentication):

    def __init__(self, query_client):
        super().__init__(query_client)

    def authenticate(self, request, methods):
        def query_client(*args, **kwargs):
            """Wraps `query_client` and passes the current request."""
            return self._original_query_client(request, *args, **kwargs)

        self.query_client = query_client
        return super().authenticate(request, methods)
