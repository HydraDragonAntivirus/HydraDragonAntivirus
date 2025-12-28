from PIL import Image, ImageOps
import os

def create_firewall_icon():
    base_path = r'c:\Users\victim\Documents\GitHub\HydraDragonRemoteDesktop\assets\HydraDragonAV.png'
    shield_asset = r'C:\Users\victim\.gemini\antigravity\brain\b5520079-f7f2-483a-a35e-830da3b7e4d1\firewall_shield_black_bg_1766604161027.png'
    output_png = r'c:\Users\victim\Documents\GitHub\HydraDragonRemoteDesktop\assets\firewall.png'
    output_ico = r'c:\Users\victim\Documents\GitHub\HydraDragonRemoteDesktop\assets\firewall.ico'
    
    if not os.path.exists(base_path):
        print(f"Error: {base_path} not found")
        return
    if not os.path.exists(shield_asset):
        print(f"Error: {shield_asset} not found")
        return

    # Load base dragon image
    dragon_img = Image.open(base_path).convert("RGBA")
    
    # Load shield asset
    shield_img = Image.open(shield_asset).convert("RGBA")
    
    # Process shield: treat black (or very dark) as transparent
    # Better yet, since it's a "glowing" icon, we can use the maximum of color channels or just a threshold
    datas = shield_img.getdata()
    new_data = []
    for item in datas:
        # If R+G+B is very low, make it transparent
        if item[0] < 10 and item[1] < 10 and item[2] < 10:
            new_data.append((0, 0, 0, 0))
        else:
            new_data.append(item)
    shield_img.putdata(new_data)
    
    # Resize shield to be an overlay (e.g., 50% of dragon size)
    d_w, d_h = dragon_img.size
    s_size = int(d_w * 0.5)
    shield_img = shield_img.resize((s_size, s_size), Image.Resampling.LANCZOS)
    
    # Create final image
    # Place shield in bottom-right
    final_img = dragon_img.copy()
    offset = (d_w - s_size - 10, d_h - s_size - 10)
    final_img.alpha_composite(shield_img, dest=offset)
    
    # Save PNG
    final_img.save(output_png)
    print(f"Saved {output_png}")
    
    # Save ICO
    final_img.save(output_ico, format='ICO', sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
    print(f"Saved {output_ico}")

if __name__ == "__main__":
    create_firewall_icon()
