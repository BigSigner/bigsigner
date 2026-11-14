"""A bounded text editor that indexes lines and paints only the visible rows."""

from array import array
from bisect import bisect_right

from PIL import Image, ImageDraw

from .canvas import BLUE, INK, LINE, TITLE_SIZE, WHITE, font


class TextEditor:
    def __init__(self, limit=50_000):
        self.limit = limit
        self.load("")

    def load(self, text):
        self.text = self.original = text
        self.cursor = 0
        self.keyboard = False
        self.scroll = self.scroll_max = 0
        self.reveal = False
        self.box = None
        self._revision = 0
        self._layout_key = None
        self.starts = array("I")
        self.ends = array("I")

    @property
    def changed(self):
        return self.text != self.original

    def type(self, key):
        if key == "backspace":
            if not self.cursor:
                return
            count = 2 if self.text[max(0, self.cursor - 2):self.cursor] == "\r\n" else 1
            self.text = self.text[:self.cursor - count] + self.text[self.cursor:]
            self.cursor -= count
        else:
            if key == "enter":
                key = "\r\n" if "\r\n" in self.text else "\n"
            if len(self.text.encode("utf-8")) + len(key.encode("utf-8")) > self.limit:
                return
            self.text = self.text[:self.cursor] + key + self.text[self.cursor:]
            self.cursor += len(key)
        self._revision += 1
        self.reveal = True

    def _index(self, columns):
        key = (self._revision, columns)
        if self._layout_key == key:
            return
        self._layout_key = key
        self.starts = array("I")
        self.ends = array("I")
        start = i = column = 0
        while i < len(self.text):
            if self.text[i] in "\r\n":
                self.starts.append(start)
                self.ends.append(i)
                i += 2 if self.text[i:i + 2] == "\r\n" else 1
                start, column = i, 0
            else:
                if column == columns:
                    self.starts.append(start)
                    self.ends.append(i)
                    start, column = i, 0
                i += 1
                column += 1
        self.starts.append(start)
        self.ends.append(i)

    def paint(self, frame, box):
        self.box = box
        self.pad = 12
        self.line_h = TITLE_SIZE + 8
        face = font(TITLE_SIZE, mono=True)
        self.char_w = frame.draw.textlength("0", font=face)
        columns = max(1, int((box[2] - box[0] - 2 * self.pad) // self.char_w))
        self._index(columns)
        width, height = box[2] - box[0], box[3] - box[1]
        self.scroll_max = max(0, 2 * self.pad + len(self.starts) * self.line_h - height)
        row = max(0, bisect_right(self.starts, self.cursor) - 1)
        if self.reveal:
            self.reveal = False
            target = self.pad + row * self.line_h
            if target < self.scroll:
                self.scroll = target
            elif target + self.line_h > self.scroll + height:
                self.scroll = target + self.line_h - height
        self.scroll = max(0, min(self.scroll, self.scroll_max))
        layer = Image.new("RGB", (width, height), WHITE)
        draw = ImageDraw.Draw(layer)
        first = max(0, int((self.scroll - self.pad) // self.line_h))
        last = min(len(self.starts), first + height // self.line_h + 3)
        for index in range(first, last):
            y = self.pad + index * self.line_h - self.scroll
            visible = self.text[self.starts[index]:self.ends[index]].replace("\t", "→")
            draw.text((self.pad, y), visible, font=face, fill=INK)
        if self.keyboard:
            y = self.pad + row * self.line_h - self.scroll
            column = min(self.ends[row] - self.starts[row], self.cursor - self.starts[row])
            x = self.pad + column * self.char_w
            if 0 <= y < height:
                draw.line((x, y + 4, x, min(height - 4, y + self.line_h - 4)), fill=BLUE, width=2)
        frame.image.paste(layer, (box[0], box[1]))
        frame.draw = ImageDraw.Draw(frame.image)
        frame.draw.rounded_rectangle(box, radius=12, outline=LINE, width=2)
        frame.hit(box, "fs-focus", "Text")

    def focus(self, x, y):
        if self.box is not None and self.starts:
            row = int((y - self.box[1] + self.scroll - self.pad) // self.line_h)
            row = max(0, min(row, len(self.starts) - 1))
            column = round((x - self.box[0] - self.pad) / self.char_w)
            self.cursor = self.starts[row] + max(0, min(column, self.ends[row] - self.starts[row]))
        self.keyboard = True
        self.reveal = True
