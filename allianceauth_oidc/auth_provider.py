import time
import uuid
import jwt
from django.utils import dateformat, timezone
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauth2_provider.settings import oauth2_settings

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
    token = {
        'iss': issuer_url,
        'aud': request.client_id,
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