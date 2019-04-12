
class BaseDocument:
    def __init__(self, raw_content):
        self.raw_content = raw_content

    def get_bytes(self):
        return self.raw_content

    def __str__(self):
        return self.raw_content.decode('utf-8')
