class Response:
    identifier = None
    response_hash = None

    def __init__(self, identifier, response_hash):
        self.identifier = identifier
        self.response_hash = response_hash