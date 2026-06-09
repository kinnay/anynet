
from collections.abc import Callable, Iterable

import struct


Float = float


class StreamOut:
    """Implements a memory output stream."""

    _endian: str
    _data: bytearray
    _pos: int
    _stack: list[int]

    def __init__(self, endian: str):
        self._endian = endian
        self._data = bytearray()
        self._pos = 0
        self._stack = []
        
    def push(self) -> None:
        """Pushes the current position of the stream onto a stack."""
        self._stack.append(self._pos)
    
    def pop(self) -> None:
        """Pops the position of the stream from the stack."""
        self._pos = self._stack.pop()
        
    def get(self) -> bytes:
        """Returns the current memory buffer of the output stream."""
        return bytes(self._data)
    
    def size(self) -> int:
        """Returns the current size of the output stream."""
        return len(self._data)
    
    def tell(self) -> int:
        """Returns the current position of the output stream."""
        return self._pos

    def seek(self, pos: int) -> None:
        """
        Changes the current position of the input stream. Expands the output
        buffer if the stream is moved past the end of the memory buffer.
        """
        if pos > len(self._data):
            self._data += bytes(pos - len(self._data))
        self._pos = pos
    
    def skip(self, num: int) -> None:
        """
        Skips num bytes in the output stream, inserting zeros if the stream is
        moved past the end of the buffer.
        """
        self.seek(self._pos + num)
    
    def align(self, num: int) -> None:
        """Advances the current position until it is a multiple of num."""
        self.skip((num - self._pos % num) % num)

    def available(self) -> int:
        """
        Returns the number of bytes between the current position and the end of
        the output buffer.
        """
        return len(self._data) - self._pos
    
    def eof(self) -> bool:
        """Returns whether the stream is at the end of the output buffer."""
        return self._pos >= len(self._data)
        
    def write(self, data: bytes) -> None:
        """
        Writes data to the output buffer and advances the current position.
        """
        self._data[self._pos : self._pos + len(data)] = data
        self._pos += len(data)
        
    def pad(self, num: int, char: bytes = b"\0") -> None:
        """Writes num copies of char to the output stream."""
        self.write(char * num)
        
    def ascii(self, data: str) -> None:
        """Writes ASCII data to the output stream."""
        self.write(data.encode("ascii"))
        
    def u8(self, value: int) -> None:
        """Writes an 8-bit unsigned integer to the stream."""
        self.write(bytes([value]))
    
    def u16(self, value: int) -> None:
        """Writes a 16-bit unsigned integer to the stream."""
        self.write(struct.pack(self._endian + "H", value))
    
    def u32(self, value: int) -> None:
        """Writes a 32-bit unsigned integer to the stream."""
        self.write(struct.pack(self._endian + "I", value))

    def u64(self, value: int) -> None:
        """Writes a 64-bit unsigned integer to the stream."""
        self.write(struct.pack(self._endian + "Q", value))

    def s8(self, value: int) -> None:
        """Writes an 8-bit signed integer to the stream."""
        self.write(struct.pack("b", value))
    
    def s16(self, value: int) -> None:
        """Writes a 16-bit signed integer to the stream."""
        self.write(struct.pack(self._endian + "h", value))
    
    def s32(self, value: int) -> None:
        """Writes a 32-bit signed integer to the stream."""
        self.write(struct.pack(self._endian + "i", value))
    
    def s64(self, value: int) -> None:
        """Writes a 64-bit signed integer to the stream."""
        self.write(struct.pack(self._endian + "q", value))
    
    def u24(self, value: int) -> None:
        """Writes a 24-bit unsigned integer to the stream."""
        if self._endian == ">":
            self.u16(value >> 8)
            self.u8(value & 0xFF)
        else:
            self.u8(value & 0xFF)
            self.u16(value >> 8)
    
    def float(self, value: Float) -> None:
        """Writes a 32-bit floating point value to the stream."""
        self.write(struct.pack(self._endian + "f", value))
    
    def double(self, value: Float) -> None:
        """Writes a 64-bit floating point value to the stream."""
        self.write(struct.pack(self._endian + "d", value))
    
    def bool(self, value: bool) -> None:
        """Writes a boolean to the stream as an 8-bit integer (0 or 1)."""
        self.u8(1 if value else 0)
    
    def char(self, value: str) -> None:
        """Writes an 8-bit unicode character to the stream."""
        self.u8(ord(value))
    
    def wchar(self, value: str) -> None:
        """Writes a 16-bit unicode character to the stream."""
        self.u16(ord(value))
    
    def chars(self, data: str) -> None:
        """Writes a sequence of 8-bit unicode characters to the stream."""
        self.repeat(data, self.char)
    
    def wchars(self, data: str) -> None:
        """Writes a sequence of 16-bit unicode characters to the stream."""
        self.repeat(data, self.wchar)
    
    def repeat[T](self, list: Iterable[T], func: Callable[[T], None]) -> None:
        """
        Invokes func on each element of list. This method can be used to write
        a list of values of a specific type to the stream.
        """
        for value in list:
            func(value)


class StreamIn:
    """Implements a memory input stream."""

    _endian: str
    _data: bytes
    _pos: int
    _stack: list[int]

    def __init__(self, data: bytes, endian: str):
        self._endian = endian
        self._data = data
        self._pos = 0
        self._stack = []
        
    def push(self) -> None:
        """Pushes the current position of the stream onto a stack."""
        self._stack.append(self._pos)
    
    def pop(self) -> None:
        """Pops the position of the stream from the stack."""
        self._pos = self._stack.pop()
        
    def get(self) -> bytes:
        """Returns the memory buffer of the input stream."""
        return self._data
    
    def size(self) -> int:
        """Returns the size of the input stream."""
        return len(self._data)
    
    def tell(self) -> int:
        """Returns the current position of the input stream."""
        return self._pos
    
    def seek(self, pos: int) -> None:
        """
        Changes the current position of the input stream. Raises OverflowError
        if the stream is moved past the end of the memory buffer.
        """
        if pos > self.size():
            raise OverflowError("Buffer overflow")
        self._pos = pos
    
    def skip(self, num: int) -> None:
        """Skip num bytes in the input stream."""
        self.seek(self._pos + num)
    
    def align(self, num: int) -> None:
        """Advances the current position until it is a multiple of num."""
        self.skip((num - self._pos % num) % num)
    
    def eof(self) -> bool:
        """Returns whether the stream is currently at the end of the buffer."""
        return self._pos == len(self._data)
    
    def available(self) -> int:
        """
        Returns the number of bytes between the current position and the end of
        the input buffer.
        """
        return len(self._data) - self._pos
    
    def peek(self, num: int) -> bytes:
        """
        Returns num bytes from the input buffer without advancing the position.
        """
        if self.available() < num:
            raise OverflowError("Buffer overflow")
        return self._data[self._pos : self._pos + num]
        
    def read(self, num: int) -> bytes:
        """
        Returns num bytes from the input buffer and advances the current
        position.
        """
        data = self.peek(num)
        self.skip(num)
        return data
        
    def readall(self) -> bytes:
        """Reads all remaining bytes from the input buffer."""
        return self.read(self.available())
        
    def pad(self, num: int, char: bytes = b"\0") -> None:
        """
        Reads num bytes from the input buffer. If any of the read bytes is
        different from char, ValueError is raised.
        """
        if self.read(num) != char * num:
            raise ValueError("Incorrect padding")
            
    def ascii(self, num: int) -> str:
        """
        Reads num ascii characters from the stream. 
        """
        return self.read(num).decode("ascii")
        
    def u8(self) -> int:
        "Reads an 8-bit unsigned integer from the stream."
        return self.read(1)[0]
    
    def u16(self) -> int:
        """Reads a 16-bit unsigned integer from the stream."""
        return struct.unpack(self._endian + "H", self.read(2))[0]
    
    def u32(self) -> int:
        """Reads a 32-bit unsigned integer from the stream."""
        return struct.unpack(self._endian + "I", self.read(4))[0]
    
    def u64(self) -> int:
        """Reads a 64-bit unsigned integer from the stream."""
        return struct.unpack(self._endian + "Q", self.read(8))[0]
    
    def s8(self) -> int:
        """Reads an 8-bit signed integer from the stream."""
        return struct.unpack("b", self.read(1))[0]
    
    def s16(self) -> int:
        """Reads a 16-bit signed integer from the stream."""
        return struct.unpack(self._endian + "h", self.read(2))[0]
    
    def s32(self) -> int:
        """Reads a 32-bit signed integer from the stream."""
        return struct.unpack(self._endian + "i", self.read(4))[0]
    
    def s64(self) -> int:
        """Reads a 64-bit signed integer from the stream."""
        return struct.unpack(self._endian + "q", self.read(8))[0]
    
    def u24(self) -> int:
        """Reads a 24-bit unsigned integer from the stream."""
        if self._endian == ">":
            return (self.u16() << 8) | self.u8()
        return self.u8() | (self.u16() << 8)
    
    def float(self) -> Float:
        """Reads a 32-bit floating point value from the stream."""
        return struct.unpack(self._endian + "f", self.read(4))[0]
    
    def double(self) -> Float:
        """Reads a 64-bit floating point value from the stream."""
        return struct.unpack(self._endian + "d", self.read(8))[0]
    
    def bool(self) -> bool:
        """
        Reads an 8-bit integer from the stream and returns whether it is
        non-zero.
        """
        return bool(self.u8())
    
    def char(self) -> str:
        """Reads an 8-bit unicode character from the stream."""
        return chr(self.u8())
    
    def wchar(self) -> str:
        """Reads a 16-bit unicode character from the stream."""
        return chr(self.u16())
    
    def chars(self, num: int) -> str:
        """Reads num 8-bit unicode characters from the stream."""
        return "".join(self.repeat(self.char, num))
    
    def wchars(self, num: int) -> str:
        """Reads num 16-bit unicode characters from the stream."""
        return "".join(self.repeat(self.wchar, num))
    
    def repeat[T](self, func: Callable[[], T], count: int) -> list[T]:
        """
        Invokes func count times and aggregates the results. This method can be
        used to read a list of values from the stream.
        """
        return [func() for i in range(count)]
        
        
class BitStreamOut(StreamOut):
    _bitpos: int
    _bitstack: list[tuple[int, int]]

    def __init__(self, endian: str):
        super().__init__(endian)
        self._bitpos = 0
        self._bitstack = []
        
    def push(self):
        self._bitstack.append((self._pos, self._bitpos))
    
    def pop(self) -> None:
        self._pos, self._bitpos = self._bitstack.pop()
    
    def seek(self, pos: int) -> None:
        super().seek(pos)
        self._bitpos = 0
    
    def seekbits(self, pos: int) -> None:
        super().seek(pos // 8)
        self._bitpos = pos % 8
        if self._bitpos != 0 and self.eof():
            self._data += b"\0"
            
    def tellbits(self) -> int:
        return self._pos * 8 + self._bitpos
    
    def bytealign(self) -> None:
        if self._bitpos != 0:
            self.skip(1)
            self._bitpos = 0
            
    def align(self, num: int) -> None:
        self.bytealign()
        super().align(num)
        
    def bit(self, value: int) -> None:
        if self._pos == len(self._data):
            self._data += b"\0"

        byte = self._data[self._pos]
        mask = 1 << (7 - self._bitpos)
        if value:
            byte |= mask
        else:
            byte &= ~mask
        self._data[self._pos] = byte
        
        self._bitpos += 1
        if self._bitpos == 8:
            self._bitpos = 0
            self._pos += 1
            
    def bits(self, value: int, num: int) -> None:
        for i in range(num):
            self.bit((value >> (num - i - 1)) & 1)
            
    def write(self, data: bytes) -> None:
        if self._bitpos == 0: #Fast method
            super().write(data)
        else: #Slow method
            for value in data:
                self.bits(value, 8)
        
        
class BitStreamIn(StreamIn):
    _bitpos: int
    _bitstack: list[tuple[int, int]]

    def __init__(self, data: bytes, endian: str):
        super().__init__(data, endian)
        self._bitpos = 0
        self._bitstack = []
        
    def push(self) -> None:
        self._bitstack.append((self._pos, self._bitpos))
    
    def pop(self) -> None:
        self._pos, self._bitpos = self._bitstack.pop()
    
    def seek(self, pos: int) -> None:
        super().seek(pos)
        self._bitpos = 0
        
    def seekbits(self, pos: int) -> None:
        if pos > len(self._data) * 8:
            raise OverflowError("Buffer overflow")
        self._pos = pos // 8
        self._bitpos = pos % 8
        
    def tellbits(self) -> int:
        return self._pos * 8 + self._bitpos
        
    def bytealign(self) -> None:
        if self._bitpos != 0:
            self.skip(1)
            self._bitpos = 0
        
    def align(self, num: int) -> None:
        self.bytealign()
        super().align(num)
        
    def bit(self) -> int:
        if self.eof():
            raise OverflowError("Buffer overflow")
        
        byte = self._data[self._pos]
        value = (byte >> (7 - self._bitpos)) & 1
        
        self._bitpos += 1
        if self._bitpos == 8:
            self._bitpos = 0
            self._pos += 1
        
        return value
        
    def bits(self, num: int) -> int:
        value = 0
        for i in range(num):
            value = (value << 1) | self.bit()
        return value
        
    def read(self, num: int) -> bytes:
        if self._bitpos == 0: #Fast method
            return super().read(num)
        else: #Slow method
            data = []
            for i in range(num):
                data.append(self.bits(8))
            return bytes(data)
