
class BaseDocument:
    def __init__(self, raw_content):
        self.raw_content = raw_content

    def get_bytes():
        return self.raw_content

    def __str__():
        return self.raw_content.decode('utf-8')

    def get_annotations():
        raise NotImplementedError("Cannot get annotations of an abstract "
                                  "document.")
