# PWA Icons

This directory should contain all the PWA icons required for the manifest.

## Required Icon Sizes

- `icon-72x72.png` - 72x72 pixels
- `icon-96x96.png` - 96x96 pixels
- `icon-128x128.png` - 128x128 pixels
- `icon-144x144.png` - 144x144 pixels
- `icon-152x152.png` - 152x152 pixels
- `icon-192x192.png` - 192x192 pixels (required for Android)
- `icon-384x384.png` - 384x384 pixels
- `icon-512x512.png` - 512x512 pixels (required for Android)

## How to Generate Icons

### Option 1: Online Tools
1. Visit https://realfavicongenerator.net/ or https://www.pwabuilder.com/imageGenerator
2. Upload your base icon (512x512 recommended)
3. Download the generated icons
4. Place them in this directory

### Option 2: ImageMagick
```bash
# Install ImageMagick first
# macOS: brew install imagemagick
# Ubuntu: sudo apt-get install imagemagick

# Generate all sizes from a base 512x512 icon
convert base-icon.png -resize 72x72 icon-72x72.png
convert base-icon.png -resize 96x96 icon-96x96.png
convert base-icon.png -resize 128x128 icon-128x128.png
convert base-icon.png -resize 144x144 icon-144x144.png
convert base-icon.png -resize 152x152 icon-152x152.png
convert base-icon.png -resize 192x192 icon-192x192.png
convert base-icon.png -resize 384x384 icon-384x384.png
convert base-icon.png -resize 512x512 icon-512x512.png
```

### Option 3: Python Script (PIL/Pillow)
```python
from PIL import Image

base_icon = Image.open('base-icon.png')
sizes = [72, 96, 128, 144, 152, 192, 384, 512]

for size in sizes:
    icon = base_icon.resize((size, size), Image.Resampling.LANCZOS)
    icon.save(f'icon-{size}x{size}.png')
```

## Temporary Placeholder Icons

For development, you can create simple placeholder icons using any image editor or use a simple colored square. The icons will be automatically generated when you run `collectstatic`.

## Notes

- All icons should be PNG format
- Icons should have a transparent background or match your app's theme
- Use maskable icons for better Android support
- The 192x192 and 512x512 sizes are required for Android PWA installation

