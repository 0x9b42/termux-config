ffx600k(){
    ffmpeg -i "$1" -c:v libx264 -b:v 600k -r 24 "${1%.*}-600k.${1#*.}"
}

# by @NotMadCode https://t.me/c/2070837098/4500/4507
ffau() {
    ffmpeg -i "$1" -c:v libx264 -crf 32 -preset normal -c:a libopus -b:a 96k -pix_fmt yuv420p "${1%.*}-au.${1#*.}"
}

ffnoau() {
    ffmpeg -i "$1" -c:v libx264 -crf 32 -preset normal -an -pix_fmt yuv420p "${1%.*}-noau.${1#*.}"
}

ffx265(){
    ffmpeg -i "$1" -c:v libx265 -preset slow -b:v 600k -pass 1 -an -f mp4 -y /dev/null && \
    ffmpeg -i "$1" -c:v libx265 -preset slow -b:v 600k -pass 2 -c:a libopus -b:a 96k "${1%.*}-sound.${1#*.}"
}

ffx265noau(){
    ffmpeg -i "$1" -c:v libx265 -preset slow -b:v 600k -pass 1 -an -f mp4 -y /dev/null && \
    ffmpeg -i "$1" -c:v libx265 -preset slow -b:v 600k -pass 2 -an "${1%.*}-nosound.${1#*.}"
}

ffx264(){
    ffmpeg -i "$1" -c:v libx264 -preset normal -b:v 500k -pass 1 -an -f mp4 -y /dev/null && \
    ffmpeg -i "$1" -c:v libx264 -preset normal -b:v 500k -pass 2 -c:a libopus -b:a 96k "${1%.*}-x264.${1#*.}"
}

ffx264noau(){
    ffmpeg -i "$1" -c:v libx264 -preset normal -b:v 500k -pass 1 -an -f mp4 -y /dev/null && \
    ffmpeg -i "$1" -c:v libx264 -preset normal -b:v 500k -pass 2 -an "${1%.*}-x264noau.${1#*.}"
}
