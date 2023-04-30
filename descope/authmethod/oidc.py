from descope.auth import Auth
from descope.common import REFRESH_SESSION_TOKEN_NAME, EndpointsV1
from descope.exceptions import (
    ERROR_TYPE_INVALID_ARGUMENT,
    ERROR_TYPE_SERVER_ERROR,
    AuthException,
)


class OIDC:
    _auth: Auth

    def __init__(self, auth: Auth):
        self._auth = auth

    def authorize_finish(self, state_id, jwt_response) -> str:
        refresh_token_jwt = jwt_response.get(REFRESH_SESSION_TOKEN_NAME).get("jwt")

        if not state_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_ARGUMENT, "state_id argument cannot be empty"
            )

        body = OIDC._compose_authorize_finish_body(state_id)
        uri = EndpointsV1.oidc_authorize_finish
        resp = self._auth.do_post(uri, body, None, refresh_token_jwt)
        if resp.status_code != 303:  # Redirect
            raise AuthException(
                500,
                ERROR_TYPE_SERVER_ERROR,
                "Response should have Redirect status code",
            )

        return resp.headers["Location"]  # return the redirect url

    @staticmethod
    def _compose_authorize_finish_body(state_id: str) -> dict:
        return {"state_id": state_id}
