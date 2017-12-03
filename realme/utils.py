from .bundles import AuthStrength

# this function is not used in this app itself
# however, it was used by downstream code like endoflife.
def realme_auth_strength(request):
    """
    Determine the RealMe authentication strength of this session.
    :param request: a Django request
    :return: the AuthStrength of the RealMe session, or None if not authenticated with RealMe
    """
    try:
        return AuthStrength[request.session.get('realme_strength')]
    except KeyError:
        return None
