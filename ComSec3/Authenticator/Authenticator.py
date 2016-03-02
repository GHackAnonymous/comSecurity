from Authenticator import Challenge
from Authenticator import Response
import hashlib
import random


class Authenticator:
    secret = 'secret'
    challenge_counter = 0
    random_generator = random.SystemRandom()

    def __init__(self, secret):
        self.secret = secret

    def check_response(self, challenge, response):
        """Check a response from the client and validate it."""
        if challenge is not None:
            expected_response = challenge.identifier + self.secret + challenge.challenge
            expected_response_hashed = hashlib.sha1(expected_response)
            if expected_response_hashed == response.response_hash:
                return True
            else:
                return False
        else:
            raise Exception

    def generate_challenge(self):
        """Generate a new challenge with a random value"""
        challenge_value = self.random_generator.randint(1, 4096)
        challenge = Challenge(self.challenge_counter, challenge_value)
        self.challenge_counter += 1
        return challenge

    def generate_response(self, challenge):
        """Generate a response based on the received challenge
        :param challenge: The received challenge
        """
        response_plain = challenge.identifier + self.secret + challenge.value
        response_hashed = hashlib.sha1(response_plain)
        response_obj = Response(challenge.identifier, response_hashed)
        return response_obj
