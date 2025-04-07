[14:22] To set the opacity of a PNG using ImageMagick, you can use the -alpha and -channel options. Here’s how you do it:

1. Set a Specific Opacity (Transparency Level)

magick input.png -alpha set -channel A -evaluate set 50% output.png

-alpha set ensures the image has an alpha channel.

-channel A targets the alpha (transparency) channel.

-evaluate set 50% sets the opacity to 50% (adjust as needed).


2. Make the PNG More Transparent (Reduce Opacity)

magick input.png -alpha set -channel A -evaluate multiply 0.5 output.png

-evaluate multiply 0.5 reduces opacity by 50% (use values between 0.0 and 1.0).


3. Set Opacity Only on Non-Transparent Pixels

If your PNG already has transparency and you only want to modify fully opaque pixels:

magick input.png -alpha set -channel A -fx 'A*0.5' output.png

This method is more flexible but slower.


Let me know if you need further tweaks!

