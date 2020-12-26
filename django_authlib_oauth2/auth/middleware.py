def token_from_cookie_middleware(get_response):
    """ Move token in cookie to header. """

    def middleware(request):
        token = request.COOKIES.get('token', None)
        if token is not None:
            request.META['HTTP_AUTHORIZATION'] = 'Bearer ' + token
        response = get_response(request)
        return response

    return middleware
