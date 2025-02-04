#!/bin/bash

# Check if the input file is provided
if [ -z "$1" ]; then
    echo "Usage: $0 <dump.cs>"
    exit 1
fi

input_file="$1"

# Extract and format the data
grep -E "class [^ ]+|\[RVA: 0x[0-9A-F]+\] \/\/ [^ ]+ [^ ]+ [^ ]+ [^ ]+ [^ ]+" "$input_file" | awk '
BEGIN {
    class_name = ""
}

/class [^ ]+/ {
    if (class_name != "") {
        print "in class " class_name ":"
        for (i = 0; i < method_count; i++) {
            print methods[i]
        }
    }
    class_name = $2
    method_count = 0
    delete methods
}

/\[RVA: 0x[0-9A-F]+\] \/\/ [^ ]+ [^ ]+ [^ ]+ [^ ]+ [^ ]+/ {
    rva_offset = substr($2, 2, length($2)-2)
    method_name = $5
    return_type = $4
    line_number = $7
    methods[method_count++] = "at " rva_offset ": " method_name " -> " return_type " (line: " line_number ")"
}

END {
    if (class_name != "") {
        print "in class " class_name ":"
        for (i = 0; i < method_count; i++) {
            print methods[i]
        }
    }
}
'
