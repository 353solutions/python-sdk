from descope.auth import Auth
from descope.common import REFRESH_SESSION_COOKIE_NAME, EndpointsV1
from descope.exceptions import ERROR_TYPE_INVALID_PUBLIC_KEY, AuthException


class WebauthN:
    _auth: Auth

    def __init__(self, auth):
        self._auth = auth

    def sign_up_start(self, identifier: str, origin: str, user: dict = None) -> dict:
        """
        Docs
        """
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Identifier cannot be empty"
            )

        if not origin:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Origin cannot be empty"
            )

        uri = EndpointsV1.signUpAuthWebauthnStart
        body = WebauthN._compose_signup_body(identifier, user, origin)
        response = self._auth.do_post(uri, body)

        return response.json()

    def sign_up_finish(self, transactionID: str, response: str) -> dict:
        """
        Docs
        """
        if not transactionID:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Transaction id cannot be empty"
            )

        if not response:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Response cannot be empty"
            )

        uri = EndpointsV1.signUpAuthWebauthnFinish
        body = WebauthN._compose_sign_up_in_finish_body(transactionID, response)
        response = self._auth.do_post(uri, body)

        resp = response.json()
        jwt_response = self._auth._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def sign_in_start(self, identifier: str, origin: str) -> dict:
        """
        Docs
        """
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Identifier cannot be empty"
            )

        if not origin:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Origin cannot be empty"
            )

        uri = EndpointsV1.signInAuthWebauthnStart
        body = WebauthN._compose_signin_body(identifier, origin)
        response = self._auth.do_post(uri, body)

        return response.json()

    def sign_in_finish(self, transaction_id: str, response: str) -> dict:
        """
        Docs
        """
        if not transaction_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Transaction id cannot be empty"
            )

        if not response:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Response cannot be empty"
            )

        uri = EndpointsV1.signInAuthWebauthnFinish
        body = WebauthN._compose_sign_up_in_finish_body(transaction_id, response)
        response = self._auth.do_post(uri, body)

        resp = response.json()
        jwt_response = self._auth._generate_jwt_response(
            resp, response.cookies.get(REFRESH_SESSION_COOKIE_NAME, None)
        )
        return jwt_response

    def add_device_start(self, identifier: str, refresh_token: str, origin: str):
        """
        Docs
        """
        if not identifier:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Identifier cannot be empty"
            )

        if not refresh_token:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Refresh token cannot be empty"
            )

        uri = EndpointsV1.deviceAddAuthWebauthnStart
        body = WebauthN._compose_add_device_start_body(identifier, origin)
        response = self._auth.do_post(uri, body, None, refresh_token)

        return response.json()

    def add_device_finish(self, transaction_id: str, response: str) -> None:
        """
        Docs
        """
        if not transaction_id:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Transaction id cannot be empty"
            )

        if not response:
            raise AuthException(
                400, ERROR_TYPE_INVALID_PUBLIC_KEY, "Response cannot be empty"
            )

        uri = EndpointsV1.deviceAddAuthWebauthnFinish
        body = WebauthN._compose_sign_up_in_finish_body(transaction_id, response)
        self._auth.do_post(uri, body)

    @staticmethod
    def _compose_signup_body(identifier: str, user: dict, origin: str) -> dict:
        body = {"user": {"externalId": identifier}}
        if user is not None:
            for key, val in user.items():
                body["user"][key] = val
        body["origin"] = origin
        return body

    @staticmethod
    def _compose_signin_body(identifier: str, origin: str) -> dict:
        body = {"externalId": identifier}
        body["origin"] = origin
        return body

    @staticmethod
    def _compose_sign_up_in_finish_body(transaction_id: str, response: str) -> dict:
        return {"transactionId": transaction_id, "response": response}

    @staticmethod
    def _compose_add_device_start_body(identifier: str, origin: str) -> dict:
        body = {"externalId": identifier}
        if origin:
            body["origin"] = origin
        return body

    @staticmethod
    def _compose_add_device_finish_body(transaction_id: str, response: str) -> dict:
        return {"transactionId": transaction_id, "response": response}