from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator, TextIO


class JsonStreamReader:
    """Small buffered character reader used to select values from large JSON objects."""

    def __init__(self, input_file: TextIO, chunk_size: int = 1024 * 1024):
        self.input_file = input_file
        self.chunk_size = chunk_size
        self.buffer = ""
        self.position = 0
        self.eof = False

    def _fill(self) -> None:
        if self.position:
            self.buffer = self.buffer[self.position :]
            self.position = 0
        if self.eof:
            return
        chunk = self.input_file.read(self.chunk_size)
        if chunk:
            self.buffer += chunk
        else:
            self.eof = True

    def peek(self) -> str:
        while self.position >= len(self.buffer) and not self.eof:
            self._fill()
        return "" if self.position >= len(self.buffer) else self.buffer[self.position]

    def get(self) -> str:
        value = self.peek()
        if value:
            self.position += 1
        return value

    def skip_whitespace(self) -> None:
        while self.peek() and self.peek().isspace():
            self.position += 1

    def expect(self, expected: str) -> None:
        self.skip_whitespace()
        actual = self.get()
        if actual != expected:
            raise ValueError(f"Expected JSON token {expected!r}, found {actual!r}.")


# This function consumes one complete JSON value while optionally retaining its text.
def read_json_value_text(reader: JsonStreamReader, *, collect: bool) -> str:
    reader.skip_whitespace()
    first = reader.peek()
    if not first:
        raise ValueError("Unexpected end of JSON while reading a value.")

    output: list[str] = []

    def consume() -> str:
        character = reader.get()
        if collect:
            output.append(character)
        return character

    if first == '"':
        escaped = False
        consume()
        while True:
            character = consume()
            if not character:
                raise ValueError("Unterminated JSON string.")
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                break
        return "".join(output)

    if first in "[{":
        opening = consume()
        closing = "]" if opening == "[" else "}"
        stack = [closing]
        in_string = False
        escaped = False
        while stack:
            character = consume()
            if not character:
                raise ValueError("Unterminated JSON container.")
            if in_string:
                if escaped:
                    escaped = False
                elif character == "\\":
                    escaped = True
                elif character == '"':
                    in_string = False
                continue
            if character == '"':
                in_string = True
            elif character == "{":
                stack.append("}")
            elif character == "[":
                stack.append("]")
            elif character == stack[-1]:
                stack.pop()
        return "".join(output)

    while reader.peek() and reader.peek() not in ",]}" and not reader.peek().isspace():
        consume()
    if not output and collect:
        raise ValueError("Invalid empty JSON scalar.")
    return "".join(output)


# This function positions the reader at one named member value inside the current JSON object.
def locate_object_member(reader: JsonStreamReader, member_name: str) -> None:
    reader.expect("{")
    reader.skip_whitespace()
    if reader.peek() == "}":
        reader.get()
        raise KeyError(member_name)

    while True:
        key_text = read_json_value_text(reader, collect=True)
        key = json.loads(key_text)
        if not isinstance(key, str):
            raise ValueError("JSON object key is not a string.")
        reader.expect(":")
        if key == member_name:
            reader.skip_whitespace()
            return
        read_json_value_text(reader, collect=False)
        reader.skip_whitespace()
        delimiter = reader.get()
        if delimiter == "}":
            raise KeyError(member_name)
        if delimiter != ",":
            raise ValueError(f"Expected ',' or '}}' after JSON member, found {delimiter!r}.")


# This function navigates a path of object-member names without loading skipped values.
def locate_json_path(reader: JsonStreamReader, member_path: tuple[str, ...]) -> None:
    if not member_path:
        raise ValueError("JSON member path must not be empty.")
    for member_name in member_path:
        locate_object_member(reader, member_name)


# This function loads one selected value from a large JSON object.
def load_json_value_at_path(path: str | Path, member_path: tuple[str, ...]) -> Any:
    with Path(path).open("r", encoding="utf-8-sig") as input_file:
        reader = JsonStreamReader(input_file)
        locate_json_path(reader, member_path)
        return json.loads(read_json_value_text(reader, collect=True))


# This function yields one element at a time from a selected JSON array.
def iter_json_array_at_path(
    path: str | Path,
    member_path: tuple[str, ...],
) -> Iterator[Any]:
    with Path(path).open("r", encoding="utf-8-sig") as input_file:
        reader = JsonStreamReader(input_file)
        locate_json_path(reader, member_path)
        reader.expect("[")
        reader.skip_whitespace()
        if reader.peek() == "]":
            reader.get()
            return

        while True:
            item_text = read_json_value_text(reader, collect=True)
            yield json.loads(item_text)
            reader.skip_whitespace()
            delimiter = reader.get()
            if delimiter == "]":
                break
            if delimiter != ",":
                raise ValueError(
                    f"Expected ',' or ']' after JSON array element, found {delimiter!r}."
                )
