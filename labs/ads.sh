main_func() {
	local util_dir="${0%/*}/bin"
	local un_bb="${util_dir}/busybox"
	local un_ads="${util_dir}/RemoveFuckingAds"
	[ -f "$un_ads" ] || ab_ort "\"RemoveFuckingAds\" binary is not installed!
   Please install it before using this patch."
	[ -f "${un_ads}.jar" ] || ab_ort "\"RemoveFuckingAds\" binary is not installed!
   Please install it before using this patch."
	setspan_green "
  RemoveFuckingAds working...
"
	local F="$(pwd)"
	local start_at="$(date +%H:%M:%S)"
	local f_name="${F##*/}"
	echo "  App: ${f_name%_src}
"
	setspan_blue "  Patching files of the current project...
"
	"${un_ads}" "$F"
	setspan_blue "
  Done!
"
	setspan_green "  Results:"
	echo "      Start time: ${start_at}
        End time: $(date +%H:%M:%S)"
}
[ -f "${0%/*}/bin/utils" ] && { . "${0%/*}/bin/utils"; } || {
	setspan_red() {
		echo "$@"
	}
	setspan_green() {
		echo "$@"
	}
	setspan_blue() {
		echo "$@"
	}
}
ab_ort() {
	local tx_t="$@"
	setspan_red "
  ${tx_t}
"
	exit
}
[ -z "$@" ] && ab_ort "No arguments passed!"
[ -e "$@" ] || ab_ort "Object
    \"${@}\"
  does not exist!"
[ -d "$@" ] || ab_ort "Object
    \"${@}\"
  is not a directory!"
[ -d "${@}/smali" ] || ab_ort "Directory
    \"${@}/smali\"
  is not exist!
  You must decompile package to smali!"
[ -d "${@}/res" ] || ab_ort "Directory
    \"${@}/res\"
  is not exist!
  You must decompile package to resources!"
cd "$@" >/dev/null 2>&1 || ab_ort "Can not 'cd' to
\"${@}\"!"
main_func
cd - >/dev/null 2>&1
exit
