import base64
import time
import uuid
import jwt
from django.utils import dateformat, timezone
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings
from urllib.parse import unquote_plus

class AllianceAuthOAuth2Validator(OAuth2Validator):
    # Extend the standard scopes to add a new "permissions" scope
    # which returns a "permissions" claim:
    oidc_claim_scope = OAuth2Validator.oidc_claim_scope
    oidc_claim_scope.update({"groups": "profile"})

    def _load_application(self, client_id, request):
        client = super()._load_application(client_id, request)
        return client
    
    def get_additional_claims(self):
        return _get_additional_claims()

def _get_additional_claims():
    out = {
        "name": lambda request: request.user.profile.main_character.character_name,
        "email": lambda request: request.user.email,
        "groups": lambda request: list(request.user.groups.all().values_list('name', flat=True)) + [request.user.profile.state.name]
    }
    return out


def to_unicode(data, encoding='UTF-8'):
    """Convert a number of different types of objects to unicode."""
    if isinstance(data, str):
        return data

    if isinstance(data, bytes):
        return str(data, encoding=encoding)

    if hasattr(data, '__iter__'):
        try:
            dict(data)
        except TypeError:
            pass
        except ValueError:
            # Assume it's a one dimensional data structure
            return (to_unicode(i, encoding) for i in data)
        else:
            # We support 2.6 which lacks dict comprehensions
            if hasattr(data, 'items'):
                data = data.items()
            return {to_unicode(k, encoding): to_unicode(v, encoding) for k, v in data}

    return data

def token_generator(request):
    now = int(time.time())
    issuer_url = oauth2_settings.oidc_issuer(request)
    aud = request.client_id
    aud = 'test'
    if aud == None:
        basic_auth = _extract_basic_auth(request)
        if basic_auth is not None:
            aud = 'none'
            b64_decoded = base64.b64decode(basic_auth)
            encoding = request.encoding or 'utf-8'
            auth_string_decoded = b64_decoded.decode(encoding)
            client_id = unquote_plus(auth_string_decoded.split(":", -1)[0])
            aud = client_id

    token = {
        'iss': issuer_url,
        'aud': aud,
        'iat': now,
        'exp': now + request.expires_in,
        'sub': request.user.id,
        'auth_time': int(dateformat.format(request.user.last_login, "U")),
        'jti': str(uuid.uuid4()),
    }

    additional_claims = _get_additional_claims()
    for scope in request.scopes:
        if scope == 'openid':
            token['name'] = additional_claims['name'](request)

        if scope == 'email':
            token['email'] = additional_claims['email'](request)

        if scope == 'profile':
            token['groups'] = additional_claims['groups'](request)

    headers = {'kid': request.client.jwk_key.thumbprint()}
    token = jwt.encode(token, oauth2_settings.OIDC_RSA_PRIVATE_KEY, 'RS256', headers=headers)
    token = to_unicode(token, "UTF-8")

    return token

def _extract_basic_auth(request):
    """
    Return authentication string if request contains basic auth credentials,
    otherwise return None
    """
    auth = request.headers.get("HTTP_AUTHORIZATION", None)
    if not auth:
        return None

    split = auth.split(" ", 1)
    if len(split) != 2:
        return None
    auth_type, auth_string = split

    if auth_type != "Basic":
        return None

    return auth_string