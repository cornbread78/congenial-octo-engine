class NodePath:
    def __init__(self, path_str: str = "04/04/00/00"):
        self.path_str = path_str
        parts = path_str.split('/')
        if len(parts) != 4:
            raise ValueError("Invalid path structure: expected 4 segments separated by '/'")
        
        self.segments = [int(p) for p in parts]

    def traversal_offset(self) -> int:
        return (
            (self.segments[0] << 24)
            ^ (self.segments[1] << 16)
            ^ (self.segments[2] << 8)
            ^ self.segments[3]
        )

    def __repr__(self) -> str:
        return f"NodePath(vector={self.path_str}, segments={self.segments})"

if __name__ == "__main__":
    path = NodePath("04/04/00/00")
    print(f"Target Vector Loaded: {path}")
    print(f"Traversal Offset: {path.traversal_offset()}")
