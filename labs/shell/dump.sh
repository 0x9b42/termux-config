su -c ls /data &>/dev/null
[ $? -ne 0 ] && echo "no root no dump :(" && exit 1

PKG=n.u.l.l
PID=$(su -c ps -A | grep $PKG | awk '{print $2}')

[ ! $PID ] && echo "app no run?" && exit 1
echo found package $PKG with pid $PID. processing...

su -c cat /proc/$PID/maps > .$PID.maps
offsets=$(
    cat .$PID.maps |
    grep -E "/data/user.*/\w+[0-9]*\.dex" |
    sed -E 's,/data/.*/(\w+[0-9]*\.dex),\1,' |
    awk '{print $6,$1}' | tr ' ' '|'
)


for i in ${offsets[@]}
do
    eval "$(echo $i |
        sed -E 's,(.*)\|(.*)-(.*),c=\1 a=$((0x\2)) b=$((0x\3)),'
    )"

    n=$((b-a))

    su -c dd if=/proc/$PID/mem of=$c bs=1 skip=$a count=$n &>/dev/null

    [[ -s "$c" ]] && echo successfully dumped: $c ||
        echo error processing $c

done

rm .$PID.maps
echo process completed
