import os
from oauth2_provider.oauth2_validators import OAuth2Validator
from oauthlib.oauth2.rfc6749 import tokens

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

def token_generator(request):
    claims = _get_additional_claims()(request)
    claims['issuer'] = os.environ.get("AA_OIDC_ISSUER")
    func = tokens.signed_token_generator(os.environ.get("AA_OIDC_RSA_PRIVATE_KEY"), **claims)
    return func(request)