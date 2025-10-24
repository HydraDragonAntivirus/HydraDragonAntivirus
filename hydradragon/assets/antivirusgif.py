from PIL import Image, ImageEnhance, ImageFilter, ImageChops, ImageDraw
import math

# Paths
src_path = "HydraDragonAVLogo.png"
protected_out = "hydra_protected.gif"
unprotected_out = "hydra_unprotected.gif"

# Load base image
base = Image.open(src_path).convert("RGBA")
w, h = base.size

# Helper: create a radial glow layer
def radial_glow(size, color=(0, 200, 255), intensity=1.0, radius_factor=0.6):
    W, H = size
    cx, cy = W / 2, H / 2
    max_r = math.hypot(cx, cy) * radius_factor
    glow = Image.new("RGBA", size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(glow)

    steps = 120
    for i in range(steps, 0, -1):
        r = max_r * (i / steps)
        alpha = int((1 - (i / steps)) * 255 * intensity)
        col = (color[0], color[1], color[2], max(0, min(255, alpha)))
        bbox = [cx - r, cy - r, cx + r, cy + r]
        draw.ellipse(bbox, fill=col)

    glow = glow.filter(ImageFilter.GaussianBlur(radius=int(max(8, max(w, h) * 0.02))))
    return glow

# --- Protected (active, glowing) animation ---
frames_prot = []
num_frames = 24
for i in range(num_frames):
    t = i / num_frames
    pulse = 0.6 + 0.4 * math.sin(2 * math.pi * t)
    aura = radial_glow((w, h), color=(0, 200, 255), intensity=pulse, radius_factor=0.55)

    flash = Image.new("RGBA", (w, h), (255, 255, 255, 0))
    if (i % 8) == 0:
        flash_draw = ImageDraw.Draw(flash)
        flash_alpha = int(90 * (1 - abs((i % 8) / 8 - 0.5) * 2))
        poly = [(w * 0.1, h * 0.2), (w * 0.9, h * 0.2), (w * 0.6, h * 0.8), (w * 0.4, h * 0.8)]
        flash_draw.polygon(poly, fill=(200, 230, 255, flash_alpha))
        flash = flash.filter(ImageFilter.GaussianBlur(radius=12))

    canvas = base.copy()
    canvas = Image.alpha_composite(canvas, aura)
    canvas = Image.alpha_composite(canvas, flash)
    frames_prot.append(canvas.convert("P", palette=Image.Palette.ADAPTIVE))

frames_prot[0].save(
    protected_out,
    save_all=True,
    append_images=frames_prot[1:],
    duration=60,
    loop=0,
    optimize=True,
)

# --- Unprotected (dim, flicker) animation ---
frames_unprot = []
num_frames = 18

enhancer = ImageEnhance.Color(base)
desat = enhancer.enhance(0.2)
dark_enh = ImageEnhance.Brightness(desat)

for i in range(num_frames):
    t = i / num_frames
    flicker = 0.75 + 0.12 * math.sin(4 * math.pi * t + 0.6)
    img = dark_enh.enhance(flicker)

    vign = Image.new("RGBA", (w, h), (0, 0, 0, 0))
    vd = ImageDraw.Draw(vign)
    steps = 60
    for s in range(steps):
        alpha = int(30 * (s / steps) * (1 - 0.5 * math.sin(2 * math.pi * t)))
        bbox = [w * 0.02 * s / steps, h * 0.02 * s / steps, w - w * 0.02 * s / steps, h - h * 0.02 * s / steps]
        vd.rectangle(bbox, fill=(0, 0, 0, alpha))

    img = Image.alpha_composite(img, vign)
    frames_unprot.append(img.convert("P", palette=Image.Palette.ADAPTIVE))

frames_unprot[0].save(
    unprotected_out,
    save_all=True,
    append_images=frames_unprot[1:],
    duration=80,
    loop=0,
    optimize=True,
)

print("✅ GIFs created:")
print(protected_out)
print(unprotected_out)
