from provmap.events.event import Event

class Parser:
    def __init__(self, filepath: str, *args, **kwargs) -> None:
        raise NotImplementedError()
    
    def parse(self, *args, **kwargs) -> list[Event]:
        raise NotImplementedError()

