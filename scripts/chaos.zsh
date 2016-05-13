#compdef chaos
#autoload

_chaos_ls () {
	_values -C 'entries' ${$(chaos ls)}
}
	
_arguments "1: :(get ls rm new help)"

local cmd
cmd=${words[2]}
case "${cmd}" in
	ls) 
		;;
        get) 
		_chaos_ls
		;;
	new) 
		;;
	rm)
		_arguments : \
			"-f --force"
		_chaos_ls
		;;
esac


