
from typing import Iterator

import string


NAME_CHARS = string.ascii_letters + string.digits + ":-_"


def decode_entities(s: str) -> str:
	s = s.replace("&quot;", '"')
	s = s.replace("&apos;", "'")
	s = s.replace("&lt;", "<")
	s = s.replace("&gt;", ">")
	s = s.replace("&amp;", "&")
	return s

def encode_entities(s: str) -> str:
	s = s.replace("&", "&amp;")
	s = s.replace("'", "&quot;")
	s = s.replace('"', "&apos;")
	s = s.replace("<", "&lt;")
	s = s.replace(">", "&gt;")
	return s


class TextStream:
	_text: str
	_pos: int

	def __init__(self, text: str):
		self._text = text
		self._pos = 0
		
	def peek(self, size: int = 1) -> str:
		if self.available() < size:
			raise OverflowError("Buffer overflow in text stream")
		return self._text[self._pos : self._pos + size]
		
	def read(self, size: int = 1) -> str:
		if self.available() < size:
			raise OverflowError("Buffer overflow in text stream")
		text = self._text[self._pos : self._pos + size]
		self._pos += size
		return text
		
	def skip(self, size: int = 1) -> None:
		self._pos += size
		
	def available(self) -> int:
		return len(self._text) - self._pos
		
	def eof(self) -> bool:
		return self._pos == len(self._text)
		
	def skip_whitespace(self) -> None:
		while not self.eof():
			char = self.peek()
			if char not in string.whitespace:
				return
			self.skip(1)


class XMLTree:
	children: list[XMLTree]
	attrs: dict[str, str]
	text: str | None
	name: str

	def __init__(self, name: str):
		self.children = []
		self.attrs = {}
		
		self.text = None
		self.name = name
	
	def __str__(self) -> str:
		return self.encode()
	
	def __contains__(self, name: str) -> bool:
		for node in self.children:
			if node.name == name:
				return True
		return False
	
	def __getitem__(self, name: str) -> XMLTree:
		for node in self.children:
			if node.name == name:
				return node
		raise KeyError(name)
		
	def __iter__(self) -> Iterator[XMLTree]:
		return iter(self.children)
	
	def __len__(self) -> int:
		return len(self.children)
		
	def find(self, name: str) -> list[XMLTree]:
		nodes = []
		for node in self.children:
			if node.name == name:
				nodes.append(node)
		return nodes
	
	def add(
		self, name: str, text: str | None = None, attrs: dict[str, str] = {}
	) -> XMLTree:
		node = XMLTree(name)
		node.text = text
		node.attrs = dict(attrs)
		self.children.append(node)
		return node
	
	def encode(self) -> str:
		data = "<%s" %self.name
		for name, value in self.attrs.items():
			data += ' %s="%s"' %(name, encode_entities(value))
		data += ">"
		
		for child in self.children:
			data += child.encode()

		if self.text is not None:
			data += encode_entities(str(self.text))
		
		data += "</%s>" %self.name
		return data
		
		
class XMLParser:
	def parse(self, text: str) -> XMLTree:
		stream = TextStream(text)
		self._parse_declaration(stream)
		
		stream.skip_whitespace()
		
		tree = self._parse_tree(stream)
		
		stream.skip_whitespace()
		if not stream.eof():
			raise ValueError("XML document has data behind root tag")
		return tree
		
	def _parse_declaration(self, stream: TextStream) -> None:
		if stream.peek(6) == "<?xml ":
			stream.read(6)
			
			self._parse_declaration_attribs(stream)
			
			if stream.read() != "?":
				raise ValueError("XML declaration is invalid")
			stream.skip_whitespace()
			
			if stream.read() != ">":
				raise ValueError("XML declaration is invalid")
			
	def _parse_declaration_attribs(self, stream: TextStream) -> None:
		version = self._parse_fixed_attribute(stream, "version")
		if version != "1.0":
			raise ValueError("XML version must be 1.0")
		if stream.peek() == "?": return
		
		encoding = self._parse_fixed_attribute(stream, "encoding")
		if stream.peek() == "?": return
		
		standalone = self._parse_fixed_attribute(stream, "standalone")
		if standalone not in ["yes", "no"]:
			raise ValueError("standalone must be either yes of no")
			
	def _parse_tree(self, stream: TextStream) -> XMLTree:
		if stream.read() != "<":
			raise ValueError("Unexpected character in XML document")
			
		stream.skip_whitespace()
		
		name = self._parse_name(stream)
		tree = XMLTree(name)
		
		stream.skip_whitespace()
		
		char = stream.peek()
		while char not in "/>":
			name, value = self._parse_attribute(stream)
			if name in tree.attrs:
				raise ValueError("Duplicate attributein XML document")
			tree.attrs[name] = value
			char = stream.peek()
		
		char = stream.read()
		if char == "/":
			if stream.read() != ">":
				raise ValueError("Unexpected character in XML document")
			return tree
			
		tree.text = ""
		
		chars = stream.peek(2)
		while chars != "</":
			if chars[0] == "<":
				tree.children.append(self._parse_tree(stream))
			else:
				tree.text += chars[0]
				stream.skip()
			chars = stream.peek(2)
			
		tree.text = decode_entities(tree.text)
			
		stream.skip(2)
		stream.skip_whitespace()
		
		name = self._parse_name(stream)
		if name != tree.name:
			raise ValueError(
				"Closing tag has unexpected name: '%s' (expected '%s')" %(name, tree.name)
			)
			
		stream.skip_whitespace()
		if stream.read() != ">":
			raise ValueError("Unexpected character in XML document")
		
		return tree	
			
	def _parse_fixed_attribute(self, stream: TextStream, attr: str) -> str:
		name, value = self._parse_attribute(stream)
		if name != attr:
			raise ValueError("Expected '%s' attribute, not '%s'" %(attr, name))
		return value
		
	def _parse_attribute(self, stream: TextStream) -> tuple[str, str]:
		stream.skip_whitespace()
		key = self._parse_name(stream)
		stream.skip_whitespace()
		if stream.read() != "=":
			raise ValueError("Expected '=' after attribute name")
		stream.skip_whitespace()
		value = self._parse_string(stream)
		stream.skip_whitespace()
		return key, value
		
	def _parse_string(self, stream: TextStream) -> str:
		strchar = stream.read()
		if strchar not in ["'", '"']:
			raise ValueError("Expected string attribute")
		
		string = ""
		char = stream.read()
		while char != strchar:
			string += char
			char = stream.read()
		
		string = " ".join(string.split())
		string = decode_entities(string)
		return string
		
	def _parse_name(self, stream: TextStream) -> str:
		name = ""
		char = stream.peek()
		while char in NAME_CHARS:
			name += char
			stream.skip()
			char = stream.peek()
		return name
		
		
def parse(text: str) -> XMLTree:
	parser = XMLParser()
	try:
		return parser.parse(text)
	except OverflowError:
		raise ValueError("XML document is incomplete")
