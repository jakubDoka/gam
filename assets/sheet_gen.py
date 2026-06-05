import sys
from PIL import Image

def make_spritesheet(input_path, output_path, angles=8):
    img = Image.open(input_path).convert("RGBA")
    w, h = img.size
    
    frames = []
    for i in range(angles):
        angle = i * (360 / angles)
        # rotate with NEAREST, no expand = preserves original canvas size
        rotated = img.rotate(-angle, resample=Image.NEAREST, expand=False)
        frames.append(rotated)
    
    # pack horizontally, all frames same size so no overflow
    sheet = Image.new("RGBA", (w * angles, h), (0, 0, 0, 0))
    for i, frame in enumerate(frames):
        sheet.paste(frame, (i * w, 0))
    
    sheet.save(output_path)
    print(f"Saved {angles} frames at {w}x{h} each → {w*angles}x{h} sheet")

make_spritesheet(sys.argv[1], sys.argv[2], angles=32)
