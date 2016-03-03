import hashlib
import random

from .Challenge import Challenge
from .Response import Response


class Authenticator:
    HEADER_LENGTH = 4
    REQUEST_TYPE = 0x00
    CHALLENGE_TYPE = 0x01
    RESPONSE_TYPE = 0x02
    SUCCESS_TYPE = 0x03
    FAILURE_TYPE = 0x04

    secret = 'secret'
    headerLength = 4
    challenge_counter = 0
    random_generator = random.SystemRandom()

    def __init__(self, secret):
        self.secret = secret

    def check_response(self, challenge, response):
        """Check a response from the client and validate it.
        :param response:
        :param challenge:
        """
        if challenge is not None:
            expected_response = challenge.identifier + self.secret + challenge.challenge
            expected_response_hashed = hashlib.sha1(expected_response)
            if expected_response_hashed == response.response_hash:
                return True
            else:
                return False
        else:
            raise Exception

    def generate_challenge(self, name):
        """Generate a new challenge with a random value
        :param name:
        """
        challenge_value = self.random_generator.randint(1, 4096)
        challenge = Challenge.Challenge(self.challenge_counter, challenge_value, name)
        self.challenge_counter += 1
        return challenge

    def generate_response(self, challenge, name):
        """Generate a response based on the received challenge
        :param name:
        :param challenge: The received challenge
        """
        response_plain = challenge.identifier + self.secret + challenge.value
        response_hashed = hashlib.sha1(response_plain)
        response_obj = Response.Response(challenge.identifier, response_hashed, name)
        return response_obj

