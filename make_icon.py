"""Generates assets/icon.png and assets/icon.ico (run: python make_icon.py)."""
from PIL import Image, ImageDraw
import os

S = 1024
img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
# rounded square with vertical blue gradient
grad = Image.new("RGBA", (S, S))
gd = ImageDraw.Draw(grad)
for y in range(S):
    t = y / S
    gd.line([(0, y), (S, y)], fill=(int(37 + 20 * t), int(99 - 30 * t), int(235 - 60 * t), 255))
mask = Image.new("L", (S, S), 0)
ImageDraw.Draw(mask).rounded_rectangle((32, 32, S - 32, S - 32), radius=230, fill=255)
img.paste(grad, (0, 0), mask)
d = ImageDraw.Draw(img)
# white shield
cx = S // 2
shield = [(cx, 170), (780, 270), (780, 520), (cx, 860), (244, 520), (244, 270)]
d.polygon(shield, fill=(255, 255, 255, 255))
# check mark
d.line([(380, 500), (470, 600), (660, 390)], fill=(37, 99, 235, 255), width=70, joint="curve")
for x, y in [(380, 500), (470, 600), (660, 390)]:
    d.ellipse((x - 35, y - 35, x + 35, y + 35), fill=(37, 99, 235, 255))
os.makedirs("assets", exist_ok=True)
img.resize((256, 256), Image.LANCZOS).save("assets/icon.png")
img.save("assets/icon.ico", sizes=[(256, 256), (128, 128), (64, 64), (48, 48), (32, 32), (24, 24), (16, 16)])
print("icon written")
