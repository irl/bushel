
import json
import requests

class CollecTorFile:
    def __init__(self, path, size, last_modified):
        self.path = path
        self.size = size
        self.last_modified = last_modified

    def __repr__(self):
        return (f"<CollecTorFile path={self.path} size={self.size} "
                 "last_modified={self.last_modified}>")

    def get_bytes(self):
        r = requests.get(self.path)
        return r.content

class CollecTorIndex:
    def __init__(self, content):
        self._data = json.loads(content)

    def directory_contents(self, path):
        raw_contents = self.raw_directory_contents(path)
        path = self._data['path'] + "/" + path
        return [CollecTorFile(path + "/" + x['path'],
                              x['size'],
                              x['last_modified']) for x in raw_contents]

    def raw_directory_contents(self, path, current_index=None):
        if current_index is None:
            current_index = self._data
        path_parts = path.split("/", 1)
        for directory in current_index['directories']:
            if directory['path'] == path_parts[0]:
                if len(path_parts) == 2:
                    return self.raw_directory_contents(path_parts[1], directory)
                else:
                    return directory['files']
            

    @classmethod
    def from_collector(cls, path="https://collector.torproject.org"):
        r = requests.get(path + "/index/index.json")
        return cls(r.text)
