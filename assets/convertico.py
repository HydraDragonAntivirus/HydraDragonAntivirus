import imageio
from PIL import Image

# Read the PNG file
png_image_path = "HydraDragonAV.png"
image = imageio.imread(png_image_path)

# Convert the image to a PIL Image object
pil_image = Image.fromarray(image)

# Save the image as an ICO file
ico_image_path = "HydraDragonAV.ico"
pil_image.save(ico_image_path, format='ICO')

print(f"{png_image_path} has been successfully converted to {ico_image_path}.")