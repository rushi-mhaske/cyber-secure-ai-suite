#!/usr/bin/env python3
"""
Generate placeholder PWA icons
Run this script to create placeholder icons for development.
Replace these with actual branded icons before production.
"""

from PIL import Image, ImageDraw, ImageFont
import os

# Icon sizes required for PWA
SIZES = [72, 96, 128, 144, 152, 192, 384, 512]

# Create icons directory if it doesn't exist
os.makedirs(os.path.dirname(__file__), exist_ok=True)

def create_icon(size):
    """Create a placeholder icon with the specified size"""
    # Create a new image with transparent background
    img = Image.new('RGBA', (size, size), (2, 132, 199, 255))  # Primary color #0284c7
    
    # Draw a simple "D" letter
    draw = ImageDraw.Draw(img)
    
    # Try to use a font, fallback to default if not available
    try:
        # Try to use a system font
        font_size = int(size * 0.6)
        font = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", font_size)
    except:
        try:
            font = ImageFont.truetype("/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf", font_size)
        except:
            font = ImageFont.load_default()
    
    # Calculate text position (centered)
    text = "D"
    bbox = draw.textbbox((0, 0), text, font=font)
    text_width = bbox[2] - bbox[0]
    text_height = bbox[3] - bbox[1]
    position = ((size - text_width) // 2, (size - text_height) // 2 - bbox[1])
    
    # Draw white text
    draw.text(position, text, fill=(255, 255, 255, 255), font=font)
    
    # Save the icon
    filename = f"icon-{size}x{size}.png"
    filepath = os.path.join(os.path.dirname(__file__), filename)
    img.save(filepath, 'PNG')
    print(f"Created {filename}")

if __name__ == "__main__":
    print("Generating placeholder PWA icons...")
    for size in SIZES:
        create_icon(size)
    print("Done! Icons created in:", os.path.dirname(__file__))
    print("\nNote: Replace these placeholder icons with actual branded icons before production.")

