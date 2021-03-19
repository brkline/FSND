import json
from os import environ
from flask import request, _request_ctx_stack, abort
from functools import wraps
from jose import jwt
from urllib.request import urlopen

# Try to get the domain and audience from an environment variable.
# If we don't find one, then use a default.
AUTH0_DOMAIN = environ.get('AUTH0_DOMAIN', 'dev-f8a4q20m.us.auth0.com')
ALGORITHMS = ['RS256']
API_AUDIENCE = environ.get('AUTH0_AUDIENCE', 'fsnd-project03-coffee')

# AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


# Auth Header
# Code below based on Udacity Starter Code found here:
# https://github.com/udacity/FSND/blob/master/BasicFlaskAuth/app.py
def get_token_auth_header():
    '''This function checks the header to make sure it contains the
    required elements.


    Raises:
        AuthError: Missing auth header
        AuthError: Incorrect format
        AuthError: Missing the word "Bearer"

    Returns:
        [str]: The bearer token
    '''
    auth_header = request.headers.get("Authorization", None)
    if not auth_header:
        raise AuthError({"code": "authorization_header_missing",
                         "description":
                         "Authorization header is expected"}, 401)

    header_parts = auth_header.split(' ')

    if len(header_parts) != 2 or not header_parts:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must be in the format'
            ' Bearer <token>'}, 401)

    elif header_parts[0].lower() != 'bearer':
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization header must start with Bearer'}, 401)

    return header_parts[1]


def verify_decode_jwt(token):
    '''This function gets the public key from Auth0 for our domain.
    It then decodes and verifies the token.


    Args:
        token (str): [description]

    Raises:
        AuthError: Malformed
        AuthError: Token expired
        AuthError: Not from who it says it is
        AuthError: Unable to parse token
        AuthError: Missing key

    Returns:
        dict: The dict representation of the claims set, assuming the signature is valid
        and all requested data validation passes.
    '''
    # Get the public key from Auth0
    jsonurl = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(jsonurl.read())

    # Get the data in the header
    unverified_header = jwt.get_unverified_header(token)

    # Auth0 token should have a key id
    if 'kid' not in unverified_header:
        raise AuthError({
            'code': 'invalid_header',
            'description': 'Authorization malformed'
        }, 401)

    rsa_key = {}

    for key in jwks['keys']:
        if key['kid'] == unverified_header['kid']:
            rsa_key = {
                'kty': key['kty'],
                'kid': key['kid'],
                'use': key['use'],
                'n': key['n'],
                'e': key['e']
            }
            break

    # verify the token
    if rsa_key:
        try:
            # Decode and validate the token using the algorithm
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer=f'https://{AUTH0_DOMAIN}/'
            )
            return payload

        # Token Expired
        except jwt.ExpiredSignatureError:

            raise AuthError({
                'code': 'token_expired',
                'description': 'Token expired.'
            }, 401)

        # Token cannot be verified
        except jwt.JWTClaimsError:

            raise AuthError({
                'code': 'invalid_claims',
                'description': 'Incorrect claims. Please, '
                'check the audience and issuer.'
            }, 401)

        # Can't parse the token for some reason
        except Exception:

            raise AuthError({
                'code': 'invalid_header',
                'description': 'Unable to parse authentication token.'
            }, 400)
    # Can't find the key
    raise AuthError({
        'code': 'invalid_header',
        'description': 'Unable to find the appropriate key.'
    }, 400)


def check_permissions(permission, payload):
    '''Validates the payload contains the matching permission.

    Args:
        permission (string): The permission we want to find.
        payload (dict): The payload we are searching.

    Raises:
        AuthError: Matching permission not found.

    Returns:
        [bool]: Was the input permission found in the payload.
    '''
    if 'permissions' not in payload:
        abort(400)

    if permission not in payload['permissions']:
        raise AuthError({
            'code': 'unauthorized',
            'description': 'Permission Not found',
        }, 401)
    return True


def requires_auth(permission=''):
    '''This function is used to check if the authorized user has the
    appropriate permissions if applicable. 

    Args:
        permission (str, optional): Permission to check. Defaults to ''.
    '''
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            payload = verify_decode_jwt(token)
            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator
