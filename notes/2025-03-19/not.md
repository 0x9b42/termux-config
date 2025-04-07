Here's a simplified version that uses `vi` for editing notes and removes the show note functionality:

```bash
#!/bin/bash

NOTE_DIR="$HOME/notes"
TODAY=$(date +%Y-%m-%d)
NOTES_DIR="$NOTE_DIR/$TODAY"

usage() {
    echo "Usage:"
    echo "  ${0##*/} -t                 # List today's notes"
    echo "  ${0##*/} <category>          # Edit specified note"
    exit 1
}

list_notes() {
    if [ ! -d "$NOTES_DIR" ]; then
        echo "no notes available"
        return 1
    fi
    
    local notes=$(find "$NOTES_DIR" -maxdepth 1 -type f -name '*.md' -exec basename -s .md {} \;)
    [ -z "$notes" ] && echo "no notes available" || echo "$notes"
}

edit_note() {
    local category="$1"
    local clean_name=$(echo "$category" | tr -d ' ')
    local note_file="$NOTES_DIR/${clean_name}.md"
    
    mkdir -p "$NOTES_DIR"
    vi "$note_file"
    echo "Note saved to: $note_file"
}

# Option handling
while getopts "t" opt; do
    case $opt in
        t) list_notes; exit ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

# Main logic
[ ! $# ] && usage
edit_note "$1"
```

Key changes:
1. Removed `-c` option and show_note functionality
2. Added `vi` editor integration for editing notes
3. Simplified argument handling (just category name)
4. Automatic filename cleanup (spaces removed)
5. Clearer success message with path after editing
6. Single option (`-t`) for listing notes

Usage examples:
```bash
# List today's notes
./notes.sh -t

# Edit/create a note (spaces in category name will be removed)
./notes.sh meetings
./notes.sh "project ideas"
```

The script will:
1. Create the notes directory if needed
2. Open vi with the specified note file
3. Show the save path after editor closes
4. Automatically remove spaces from category names for filenames
5. List available notes with `-t` option

Note: You can change `vi` to `nano`, `vim`, or any other terminal editor of your choice.
